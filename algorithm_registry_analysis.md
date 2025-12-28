# Algorithm Registry System - Comprehensive Analysis & Updated Plan

**Date:** December 27, 2025
**Branch:** feature/v1.4.0-development
**Implementation Language:** English (code comments, docstrings, variable names)

---

## Executive Summary

This document analyzes the existing `algorithm_registry_plan.md` against the current codebase and provides a comprehensive update to ensure ALL cryptographic algorithms, hashes, KDFs, and parameters are included in the registry system.

### Key Findings

1. **Missing Algorithms in Original Plan:**
   - SHA-384 (implemented but not in plan)
   - SHA3-384 (implemented but not in plan)
   - BLAKE2s (likely implemented)
   - BLAKE3 (implemented with keyed hashing)
   - SHAKE-128, SHAKE-256 (implemented as XOFs)
   - Camellia (legacy cipher, not in plan)
   - Fernet (for legacy compatibility)
   - Argon2i variant (separate from Argon2id/d)

2. **Missing PQC Algorithms:**
   - All signature algorithms (ML-DSA, FN-DSA, SLH-DSA, MAYO, CROSS)
   - HQC family (HQC-128, HQC-192, HQC-256)
   - Hybrid modes (e.g., ML-KEM-768-chacha20, HQC-192-aes)

3. **Missing KDF Features:**
   - RandomX (memory-hard PoW-based KDF)
   - Multiple KDF rounds support
   - Salt derivation strategies

4. **Missing Hash Features:**
   - Keyed hashing (BLAKE2b/BLAKE3 with keys)
   - Multiple hash rounds configuration
   - Hash chaining with round-specific salts

---

## Complete Algorithm Inventory

### 1. Symmetric Ciphers

| Algorithm | Status | Current Implementation | Security | Notes |
|-----------|--------|----------------------|----------|-------|
| **AES-256-GCM** | ✅ Active | cryptography.AESGCM | 128-bit PQ | Standard, hardware accelerated |
| **AES-GCM-SIV** | ✅ Active | cryptography.AESGCMSIV | 128-bit PQ | Nonce-misuse resistant |
| **AES-SIV** | ✅ Active | cryptography.AESSIV | 128-bit PQ | Deterministic AEAD |
| **AES-OCB3** | ⚠️ Deprecated | cryptography.AESOCB3 | 128-bit PQ | Security concerns with short nonces |
| **ChaCha20-Poly1305** | ✅ Active | cryptography.ChaCha20Poly1305 | 128-bit PQ | Software-friendly |
| **XChaCha20-Poly1305** | ✅ Active | Custom (ChaCha20 + HKDF) | 128-bit PQ | Extended nonce space (24 bytes) |
| **Fernet** | ✅ Legacy | cryptography.Fernet | 64-bit PQ | AES-128-CBC + HMAC-SHA256 |
| **Camellia** | 🔶 Legacy | Custom CBC + HMAC | 128-bit PQ | Limited adoption |

**Registry Implementation Notes:**
- XChaCha20 uses HKDF-based nonce derivation (needs special handling)
- AES-SIV has special AEAD interface (no nonce parameter)
- Fernet has fixed key format (base64-url-encoded)
- Camellia requires CBC mode + separate HMAC

### 2. Hash Functions

| Algorithm | Status | Output Size | Implementation | Notes |
|-----------|--------|-------------|----------------|-------|
| **SHA-256** | ✅ Active | 32 bytes | hashlib.sha256 | Primary hash |
| **SHA-384** | ✅ Active | 48 bytes | hashlib.sha384 | **MISSING IN PLAN** |
| **SHA-512** | ✅ Active | 64 bytes | hashlib.sha512 | Primary hash |
| **SHA3-256** | ✅ Active | 32 bytes | hashlib.sha3_256 | Keccak-based |
| **SHA3-384** | ✅ Active | 48 bytes | hashlib.sha3_384 | **MISSING IN PLAN** |
| **SHA3-512** | ✅ Active | 64 bytes | hashlib.sha3_512 | Keccak-based |
| **BLAKE2b** | ✅ Active | 64 bytes (default) | hashlib.blake2b | Supports keyed hashing |
| **BLAKE2s** | ✅ Active | 32 bytes (default) | hashlib.blake2s | **MISSING IN PLAN** |
| **BLAKE3** | ✅ Active | Variable (XOF) | blake3 package | **MISSING IN PLAN**, keyed mode |
| **SHAKE-128** | ✅ Active | Variable (XOF) | hashlib.shake_128 | **MISSING IN PLAN** |
| **SHAKE-256** | ✅ Active | Variable (XOF) | hashlib.shake_256 | **MISSING IN PLAN** |
| **Whirlpool** | 🔶 Legacy | 64 bytes | whirlpool/pywhirlpool | Py3.13+ compatibility layer |

**Registry Implementation Notes:**
- BLAKE2b/BLAKE2s support `digest_size` parameter (1-64 bytes for b, 1-32 for s)
- BLAKE2b/BLAKE2s support `key` parameter (0-64 bytes for b, 0-32 for s)
- BLAKE3 supports keyed hashing mode
- SHAKE-128/256 are XOFs (Extendable Output Functions) - variable length output
- Current implementation uses round-specific salts for hash iterations
- Whirlpool has special Python 3.13+ loading mechanism

### 3. Key Derivation Functions (KDFs)

| Algorithm | Status | Parameters | Implementation | Notes |
|-----------|--------|------------|----------------|-------|
| **Argon2id** | ✅ Active | time_cost, memory_cost, parallelism, type | argon2.low_level | Recommended |
| **Argon2d** | ✅ Active | time_cost, memory_cost, parallelism, type | argon2.low_level | GPU-resistant |
| **Argon2i** | ✅ Active | time_cost, memory_cost, parallelism, type | argon2.low_level | **NOT IN PLAN** |
| **Balloon** | ✅ Active | time_cost, space_cost, parallelism | Custom impl | Memory-hard |
| **Scrypt** | ✅ Active | n, r, p | cryptography.Scrypt | Memory-hard |
| **PBKDF2** | ✅ Active | iterations, hash_function | cryptography.PBKDF2HMAC | Legacy/compat |
| **HKDF** | ✅ Active | hash_function, info | cryptography.HKDF | Key expansion |
| **RandomX** | ✅ Active | hash, init_rounds, passes, verify_cache | pyrx package | **NOT IN PLAN** |

**Registry Implementation Notes:**
- All KDFs support multiple rounds with per-round salt derivation
- Argon2 type mapping: 0=Argon2d, 1=Argon2i, 2=Argon2id (Type enum)
- Balloon uses custom implementation in `balloon.py`
- RandomX is PoW-based, much slower than others
- HKDF is NOT for passwords (key expansion only)
- Current code supports KDF chaining (multiple KDFs in sequence)

### 4. Post-Quantum Algorithms (KEMs)

| Algorithm | NIST Level | Key Size | Ciphertext Size | Status | Notes |
|-----------|------------|----------|-----------------|--------|-------|
| **ML-KEM-512** | 1 (AES-128) | 1568 bytes | 768 bytes | ✅ Active | FIPS 203 |
| **ML-KEM-768** | 3 (AES-192) | 2400 bytes | 1088 bytes | ✅ Active | FIPS 203 (recommended) |
| **ML-KEM-1024** | 5 (AES-256) | 3168 bytes | 1568 bytes | ✅ Active | FIPS 203 |
| **HQC-128** | 1 (AES-128) | 2249 bytes | 4481 bytes | ✅ Active | **NOT IN PLAN** |
| **HQC-192** | 3 (AES-192) | 4522 bytes | 9026 bytes | ✅ Active | **NOT IN PLAN** |
| **HQC-256** | 5 (AES-256) | 7245 bytes | 14469 bytes | ✅ Active | **NOT IN PLAN** |

**Hybrid Modes (NOT IN PLAN):**
- ML-KEM-512-hybrid (ML-KEM-512 + AES-GCM)
- ML-KEM-768-hybrid (ML-KEM-768 + AES-GCM)
- ML-KEM-1024-hybrid (ML-KEM-1024 + AES-GCM)
- ML-KEM-512-chacha20 (ML-KEM-512 + ChaCha20-Poly1305)
- ML-KEM-768-chacha20 (ML-KEM-768 + ChaCha20-Poly1305)
- ML-KEM-1024-chacha20 (ML-KEM-1024 + ChaCha20-Poly1305)
- HQC-128-hybrid, HQC-192-hybrid, HQC-256-hybrid
- HQC-128-chacha20, HQC-192-chacha20, HQC-256-chacha20

### 5. Post-Quantum Signatures (NOT IN PLAN)

| Algorithm | NIST Level | Sig Size | PK Size | SK Size | Status | Standard |
|-----------|------------|----------|---------|---------|--------|----------|
| **ML-DSA-44** | 2 (128-bit) | ~2420 bytes | 1312 bytes | 2528 bytes | ✅ Active | FIPS 204 |
| **ML-DSA-65** | 3 (192-bit) | ~3293 bytes | 1952 bytes | 4000 bytes | ✅ Active | FIPS 204 |
| **ML-DSA-87** | 5 (256-bit) | ~4595 bytes | 2592 bytes | 4864 bytes | ✅ Active | FIPS 204 |
| **FN-DSA-512** | 1 (128-bit) | ~690 bytes | 897 bytes | 1281 bytes | ✅ Active | FIPS 206 |
| **FN-DSA-1024** | 5 (256-bit) | ~1330 bytes | 1793 bytes | 2305 bytes | ✅ Active | FIPS 206 |
| **SLH-DSA-SHA2-128F** | 1 (128-bit) | 17088 bytes | 32 bytes | 64 bytes | ✅ Active | FIPS 205 |
| **SLH-DSA-SHA2-256F** | 5 (256-bit) | 49856 bytes | 64 bytes | 128 bytes | ✅ Active | FIPS 205 |
| **MAYO-1** | 1 (128-bit) | ~321 bytes | 1168 bytes | 24 bytes | ✅ Active | Round 2 |
| **MAYO-3** | 3 (192-bit) | ~577 bytes | 2656 bytes | 32 bytes | ✅ Active | Round 2 |
| **MAYO-5** | 5 (256-bit) | ~838 bytes | 5488 bytes | 40 bytes | ✅ Active | Round 2 |
| **CROSS-128** | 1 (128-bit) | ~12000 bytes | ~15000 bytes | 32 bytes | ✅ Active | Round 2 |
| **CROSS-192** | 3 (192-bit) | ~24000 bytes | ~30000 bytes | 48 bytes | ✅ Active | Round 2 |
| **CROSS-256** | 5 (256-bit) | ~40000 bytes | ~50000 bytes | 64 bytes | ✅ Active | Round 2 |

---

## Registry Architecture Updates

### Current Issues with Direct Registry Approach

The existing plan assumes all algorithms can be wrapped in a unified interface. However, **Post-Quantum algorithms have fundamentally different APIs:**

1. **PQC KEMs** (Key Encapsulation Mechanisms):
   - Operations: `keypair()`, `encapsulate(pk)`, `decapsulate(sk, ct)`
   - Hybrid modes combine PQC KEM + symmetric cipher
   - Output: (shared_secret, ciphertext) tuple

2. **PQC Signatures**:
   - Operations: `keypair()`, `sign(sk, message)`, `verify(pk, message, signature)`
   - Output: detached signatures

3. **Symmetric Ciphers** (AEAD):
   - Operations: `encrypt(key, nonce, data, aad)`, `decrypt(key, nonce, ct, aad)`
   - Output: ciphertext with integrated auth tag

### Proposed Solution: Multi-Tier Registry System

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Algorithm Registry System                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ CipherRegistry   │  │  HashRegistry    │  │   KDFRegistry    │  │
│  │  (Symmetric)     │  │                  │  │                  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                     │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │   KEMRegistry    │  │ SignatureRegistry│  │  HybridRegistry  │  │
│  │ (PQC Encryption) │  │  (PQC Signing)   │  │ (PQC + Classic)  │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Unified AlgorithmInfo with Category-Specific Fields

```python
@dataclass(frozen=True)
class AlgorithmInfo:
    """Extended to support all algorithm types."""

    # Common fields (as in plan)
    name: str
    display_name: str
    category: AlgorithmCategory  # CIPHER, HASH, KDF, KEM, SIGNATURE, HYBRID
    security_bits: int
    pq_security_bits: int
    security_level: SecurityLevel
    description: str

    # Cipher-specific
    key_size: Optional[int] = None
    nonce_size: Optional[int] = None
    tag_size: Optional[int] = None
    block_size: Optional[int] = None

    # Hash-specific
    output_size: Optional[int] = None
    supports_keyed_mode: bool = False
    is_xof: bool = False  # Extendable Output Function (SHAKE, BLAKE3)

    # KEM-specific
    public_key_size: Optional[int] = None
    secret_key_size: Optional[int] = None
    ciphertext_size: Optional[int] = None
    shared_secret_size: Optional[int] = None

    # Signature-specific
    signature_size: Optional[int] = None

    # Hybrid-specific
    base_kem_algorithm: Optional[str] = None
    symmetric_algorithm: Optional[str] = None

    # Common
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    references: Tuple[str, ...] = field(default_factory=tuple)
    nist_standard: Optional[str] = None  # e.g., "FIPS 203", "FIPS 204"
```

---

## Updated Implementation Plan

### New Registry Structure

```
openssl_encrypt/
├── modules/
│   ├── registry/
│   │   ├── __init__.py              # Public API
│   │   ├── base.py                  # AlgorithmBase, AlgorithmInfo, RegistryBase
│   │   ├── utils.py                 # Shared utilities
│   │   ├── cipher_registry.py       # Symmetric ciphers (AES-GCM, ChaCha20, etc.)
│   │   ├── hash_registry.py         # Hash functions (SHA, BLAKE, etc.)
│   │   ├── kdf_registry.py          # KDFs (Argon2, Scrypt, PBKDF2, etc.)
│   │   ├── kem_registry.py          # **NEW**: PQC KEMs (ML-KEM, HQC)
│   │   ├── signature_registry.py    # **NEW**: PQC Signatures (ML-DSA, FN-DSA, etc.)
│   │   └── hybrid_registry.py       # **NEW**: Hybrid encryption modes
│   └── ...
```

### Phase 1: Core Registries (Already in Plan)

✅ As described in original plan:
- `base.py` - Base classes
- `utils.py` - Utilities
- `cipher_registry.py` - Symmetric ciphers
- `hash_registry.py` - Hash functions
- `kdf_registry.py` - KDFs

### Phase 2: Hash Registry Additions (NEW)

Add missing hash algorithms:

```python
class SHA384(HashBase):
    """SHA-384 (SHA-2 Family)."""
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="sha384",
            display_name="SHA-384",
            category=AlgorithmCategory.HASH,
            security_bits=384,
            pq_security_bits=192,
            security_level=SecurityLevel.HIGH,
            description="SHA-2 with 384-bit output",
            output_size=48,
            block_size=128,
            aliases=("sha-384", "sha2-384"),
            references=("FIPS 180-4", "RFC 6234"),
        )

class BLAKE2s(HashBase):
    """BLAKE2s - optimized for 32-bit platforms."""
    # Similar to BLAKE2b but with 32-byte output

class BLAKE3(HashBase):
    """BLAKE3 - High-performance cryptographic hash with XOF support."""
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="blake3",
            display_name="BLAKE3",
            category=AlgorithmCategory.HASH,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.HIGH,
            description="BLAKE3 with variable output (XOF) and keyed hashing",
            output_size=64,  # Default, but variable
            is_xof=True,
            supports_keyed_mode=True,
            references=("https://github.com/BLAKE3-team/BLAKE3",),
        )

    def hash(self, data: bytes, output_length: int = 64) -> bytes:
        """Hash with variable output length (XOF)."""
        import blake3
        return blake3.blake3(data).digest(output_length)

    def hash_keyed(self, data: bytes, key: bytes, output_length: int = 64) -> bytes:
        """Keyed hashing mode."""
        import blake3
        return blake3.blake3(data, key=key).digest(output_length)

class SHAKE128(HashBase):
    """SHAKE-128 - XOF with variable output."""
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="shake128",
            display_name="SHAKE-128",
            category=AlgorithmCategory.HASH,
            security_bits=128,
            pq_security_bits=64,
            security_level=SecurityLevel.STANDARD,
            description="SHAKE-128 extendable output function (XOF)",
            output_size=64,  # Default, but variable
            is_xof=True,
            references=("FIPS 202",),
        )

    def hash(self, data: bytes, output_length: int = 64) -> bytes:
        """Hash with variable output length."""
        import hashlib
        return hashlib.shake_128(data).digest(output_length)

class SHAKE256(HashBase):
    """SHAKE-256 - XOF with variable output."""
    # Similar to SHAKE128

class Whirlpool(HashBase):
    """Whirlpool - Legacy hash with Python 3.13+ compatibility."""
    @classmethod
    def is_available(cls) -> bool:
        """Check Whirlpool availability (complex for Python 3.13+)."""
        try:
            import whirlpool
            return True
        except ImportError:
            try:
                import pywhirlpool
                return True
            except ImportError:
                return False
```

### Phase 3: KDF Registry Additions (NEW)

Add RandomX and Argon2i:

```python
class Argon2i(KDFBase):
    """Argon2i - Side-channel resistant variant."""
    params_class = Argon2Params

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="argon2i",
            display_name="Argon2i",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="Argon2i - side-channel resistant (use Argon2id for general use)",
            references=("RFC 9106",),
        )

    def derive(self, password: bytes, salt: bytes, params: Optional[Argon2Params] = None) -> bytes:
        # Force variant to 'i'
        if params is None:
            params = Argon2Params(variant="i")
        else:
            params = Argon2Params(
                output_length=params.output_length,
                salt_length=params.salt_length,
                time_cost=params.time_cost,
                memory_cost=params.memory_cost,
                parallelism=params.parallelism,
                variant="i",
            )

        argon2id = Argon2id()
        return argon2id.derive(password, salt, params)

@dataclass
class RandomXParams(KDFParams):
    """Parameters for RandomX KDF."""
    hash: str = "sha256"  # Hash algorithm for initial round
    init_rounds: int = 1  # Number of RandomX initialization rounds
    passes: int = 1  # Number of RandomX passes
    verify_cache: bool = True  # Verify cache integrity

class RandomX(KDFBase):
    """RandomX - Proof-of-Work based KDF (very slow, high security)."""
    params_class = RandomXParams

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="randomx",
            display_name="RandomX",
            category=AlgorithmCategory.KDF,
            security_bits=256,
            pq_security_bits=128,
            security_level=SecurityLevel.PARANOID,
            description="RandomX PoW-based KDF - extremely slow, very high security",
            references=("https://github.com/tevador/RandomX",),
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                import pyrx
                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    def derive(self, password: bytes, salt: bytes, params: Optional[RandomXParams] = None) -> bytes:
        """Derive key using RandomX (WARNING: Very slow!)."""
        self.check_available()

        if params is None:
            params = self.default_params()

        self.validate_params(params)

        import pyrx
        import hashlib

        # Initial hash with salt
        initial = getattr(hashlib, params.hash)(password + salt).digest()

        # Apply RandomX
        derived = initial
        for _ in range(params.passes):
            derived = pyrx.get_rx_hash(
                key=derived[:16],  # RandomX key
                data=derived,
                height=params.init_rounds,
            )

        return derived[:params.output_length]

    @classmethod
    def estimate_time(cls, params: Optional[RandomXParams] = None) -> float:
        """Estimate time (RandomX is very slow!)."""
        if params is None:
            params = cls.default_params()
        # RandomX takes ~0.5-2 seconds per hash on modern CPU
        return 1.0 * params.passes * params.init_rounds
```

### Phase 4: PQC KEM Registry (NEW)

```python
# File: openssl_encrypt/modules/registry/kem_registry.py

from abc import abstractmethod
from typing import Optional, Tuple, ClassVar
from .base import AlgorithmBase, AlgorithmInfo, AlgorithmCategory, SecurityLevel, RegistryBase

class KEMBase(AlgorithmBase):
    """Base class for Key Encapsulation Mechanisms (PQC)."""

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new keypair.

        Returns:
            Tuple of (public_key, secret_key)
        """
        pass

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret.

        Args:
            public_key: Recipient's public key

        Returns:
            Tuple of (shared_secret, ciphertext)
        """
        pass

    @abstractmethod
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret.

        Args:
            secret_key: Recipient's secret key
            ciphertext: Encapsulated ciphertext

        Returns:
            Shared secret
        """
        pass

class MLKEM512(KEMBase):
    """ML-KEM-512 - NIST FIPS 203 Level 1."""

    _available: ClassVar[Optional[bool]] = None

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-kem-512",
            display_name="ML-KEM-512",
            category=AlgorithmCategory.KEM,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="ML-KEM-512 - NIST standardized post-quantum KEM (Level 1)",
            public_key_size=800,
            secret_key_size=1632,
            ciphertext_size=768,
            shared_secret_size=32,
            aliases=("kyber512", "kyber-512"),
            references=("NIST FIPS 203",),
            nist_standard="FIPS 203",
        )

    @classmethod
    def is_available(cls) -> bool:
        if cls._available is None:
            try:
                import oqs
                cls._available = "Kyber512" in oqs.get_enabled_kem_mechanisms()
            except ImportError:
                cls._available = False
        return cls._available

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        self.check_available()
        import oqs
        kem = oqs.KeyEncapsulation("Kyber512")
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        return (public_key, secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        self.check_available()
        import oqs
        kem = oqs.KeyEncapsulation("Kyber512")
        ciphertext, shared_secret = kem.encap_secret(public_key)
        return (shared_secret, ciphertext)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        self.check_available()
        import oqs
        kem = oqs.KeyEncapsulation("Kyber512", secret_key)
        shared_secret = kem.decap_secret(ciphertext)
        return shared_secret

# Similar implementations for ML-KEM-768, ML-KEM-1024, HQC-128, HQC-192, HQC-256
```

### Phase 5: PQC Signature Registry (NEW)

```python
# File: openssl_encrypt/modules/registry/signature_registry.py

class SignatureBase(AlgorithmBase):
    """Base class for digital signature algorithms."""

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate signing keypair. Returns (public_key, secret_key)."""
        pass

    @abstractmethod
    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign a message. Returns detached signature."""
        pass

    @abstractmethod
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature. Returns True if valid."""
        pass

class MLDSA44(SignatureBase):
    """ML-DSA-44 - NIST FIPS 204 Level 2 (formerly Dilithium2)."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-dsa-44",
            display_name="ML-DSA-44",
            category=AlgorithmCategory.SIGNATURE,
            security_bits=128,
            pq_security_bits=128,
            security_level=SecurityLevel.STANDARD,
            description="ML-DSA-44 - NIST standardized lattice-based signature (Level 2)",
            public_key_size=1312,
            secret_key_size=2528,
            signature_size=2420,
            aliases=("dilithium2",),
            references=("NIST FIPS 204",),
            nist_standard="FIPS 204",
        )

    @classmethod
    def is_available(cls) -> bool:
        try:
            import oqs
            return "Dilithium2" in oqs.get_enabled_sig_mechanisms()
        except ImportError:
            return False

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        self.check_available()
        import oqs
        signer = oqs.Signature("Dilithium2")
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return (public_key, secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        self.check_available()
        import oqs
        signer = oqs.Signature("Dilithium2", secret_key)
        return signer.sign(message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self.check_available()
        import oqs
        verifier = oqs.Signature("Dilithium2")
        return verifier.verify(message, signature, public_key)
```

### Phase 6: Hybrid Encryption Registry (NEW)

```python
# File: openssl_encrypt/modules/registry/hybrid_registry.py

class HybridBase(AlgorithmBase):
    """Base class for hybrid encryption (PQC KEM + Symmetric Cipher)."""

    def __init__(self):
        self.kem = None
        self.cipher = None

    @abstractmethod
    def encrypt(self, recipient_public_key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt using hybrid mode.

        Returns:
            Tuple of (kem_ciphertext, encrypted_data, nonce)
        """
        pass

    @abstractmethod
    def decrypt(
        self,
        recipient_secret_key: bytes,
        kem_ciphertext: bytes,
        encrypted_data: bytes,
        nonce: bytes
    ) -> bytes:
        """Decrypt using hybrid mode."""
        pass

class MLKEM768Hybrid(HybridBase):
    """ML-KEM-768 + AES-256-GCM hybrid encryption."""

    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-kem-768-hybrid",
            display_name="ML-KEM-768-Hybrid",
            category=AlgorithmCategory.HYBRID,
            security_bits=192,
            pq_security_bits=128,  # Limited by AES-256
            security_level=SecurityLevel.HIGH,
            description="ML-KEM-768 + AES-256-GCM hybrid encryption",
            base_kem_algorithm="ml-kem-768",
            symmetric_algorithm="aes-256-gcm",
            aliases=("kyber768-hybrid",),
            references=("NIST FIPS 203", "NIST SP 800-38D"),
        )

    def __init__(self):
        super().__init__()
        from .kem_registry import KEMRegistry
        from .cipher_registry import CipherRegistry
        self.kem = KEMRegistry.default().get("ml-kem-768")
        self.cipher = CipherRegistry.default().get("aes-256-gcm")

    def encrypt(self, recipient_public_key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        # Step 1: KEM encapsulation
        shared_secret, kem_ciphertext = self.kem.encapsulate(recipient_public_key)

        # Step 2: Derive symmetric key from shared secret
        import hashlib
        symmetric_key = hashlib.sha256(shared_secret).digest()

        # Step 3: Encrypt with AES-GCM
        nonce = self.cipher.generate_nonce()
        encrypted_data = self.cipher.encrypt(symmetric_key, nonce, plaintext)

        return (kem_ciphertext, encrypted_data, nonce)

    def decrypt(
        self,
        recipient_secret_key: bytes,
        kem_ciphertext: bytes,
        encrypted_data: bytes,
        nonce: bytes
    ) -> bytes:
        # Step 1: KEM decapsulation
        shared_secret = self.kem.decapsulate(recipient_secret_key, kem_ciphertext)

        # Step 2: Derive symmetric key
        import hashlib
        symmetric_key = hashlib.sha256(shared_secret).digest()

        # Step 3: Decrypt with AES-GCM
        plaintext = self.cipher.decrypt(symmetric_key, nonce, encrypted_data)

        return plaintext
```

---

## Critical Questions for Implementation

### 1. Branching Strategy

**Question:** Should we implement this on `feature/v1.4.0-development` or create a new branch?

**Recommendation:** Create a new branch `feature/algorithm-registry` from `feature/v1.4.0-development`:
- This is a major refactor affecting core cryptographic operations
- Allows isolated development and testing
- Can be merged back to `feature/v1.4.0-development` when stable
- Reduces risk of breaking existing features

```bash
git checkout feature/v1.4.0-development
git pull origin feature/v1.4.0-development
git checkout -b feature/algorithm-registry
```

### 2. Backward Compatibility

**Question:** How should we handle the migration of existing code that uses direct cryptography imports?

**Options:**
a. **Gradual Migration** - Keep existing code, add registry alongside
b. **Wrapper Approach** - Registry provides wrappers, old code uses them transparently
c. **Clean Break** - Refactor all existing code to use registry

**Recommendation:** **Gradual Migration (Option A)**
- Phase 1: Implement registry system
- Phase 2: Add `@deprecated` warnings to old direct imports
- Phase 3: Migrate code module-by-module
- Phase 4: Remove old code in v2.0

### 3. PQC Algorithm Organization

**Question:** Should PQC algorithms be in separate registries (KEMRegistry, SignatureRegistry, HybridRegistry) or unified with CipherRegistry?

**Recommendation:** **Separate registries** because:
- Different APIs (encapsulate/decapsulate vs encrypt/decrypt)
- Different use cases (key exchange vs data encryption)
- Clearer documentation and discovery
- Easier to maintain

### 4. Algorithm Aliases and Deprecation

**Question:** How should we handle deprecated algorithm names (Kyber* → ML-KEM-*, Dilithium* → ML-DSA-*)?

**Recommendation:**
- Register both names (canonical + aliases)
- Log deprecation warnings when aliases are used
- Include migration guide in warnings
- Remove aliases in v2.0

Example:
```python
class MLKEM768(KEMBase):
    @classmethod
    def info(cls) -> AlgorithmInfo:
        return AlgorithmInfo(
            name="ml-kem-768",  # Canonical
            aliases=("kyber768", "kyber-768"),  # Deprecated
            # ...
        )
```

### 5. Test Strategy

**Question:** How should we test the registry system with so many algorithms?

**Recommendation:**
- **Unit tests** for each algorithm class
- **Integration tests** for registry operations (get, list, availability)
- **Compatibility tests** between old and new code
- **Performance benchmarks** to ensure no regression
- **Known Answer Tests (KATs)** for crypto correctness

### 6. Security Level Classification

**Question:** Should we adjust security levels for some algorithms?

Current concerns:
- PBKDF2 marked as LEGACY - correct
- AES-OCB3 marked with warnings - correct
- Whirlpool marked as LEGACY - correct

**Recommendation:** Keep current classification, add warnings in code.

### 7. Configuration Wizard Integration

**Question:** How should config wizard use the registry system?

**Recommendation:**
```python
def _configure_hash_algorithms(self):
    """Configure hash algorithms using registry."""
    from ..registry import HashRegistry

    registry = HashRegistry.default()
    available = registry.list_available()

    print("\nAvailable hash algorithms:")
    for name, info in available.items():
        security_icon = self._get_security_icon(info.security_level)
        print(f"  {security_icon} {info.display_name} - {info.description}")

    # User selection...
```

### 8. Telemetry and Validation

**Question:** How should telemetry system integrate with registry?

**Recommendation:**
```python
# In telemetry system
from openssl_encrypt.modules.registry import CipherRegistry, HashRegistry, KDFRegistry

def get_allowed_values():
    """Get all valid algorithm names dynamically."""
    allowed = {}
    allowed["ciphers"] = CipherRegistry.default().allowed_values()
    allowed["hashes"] = HashRegistry.default().allowed_values()
    allowed["kdfs"] = KDFRegistry.default().allowed_values()
    return allowed
```

### 9. Documentation Strategy

**Question:** Should we generate algorithm documentation from registry?

**Recommendation:** Yes! Create CLI command:
```bash
python -m openssl_encrypt.cli algorithms info ml-kem-768
python -m openssl_encrypt.cli algorithms list --category kem
python -m openssl_encrypt.cli algorithms compare ml-kem-768 hqc-192
```

### 10. Performance Considerations

**Question:** Will registry abstraction add overhead?

**Answer:** Minimal. Registry provides:
- One-time lookup cost (cached singleton)
- No runtime overhead after instantiation
- Same underlying cryptography library calls

**Recommendation:** Add benchmark tests to verify.

---

## Implementation Timeline

### Phase 1: Foundation (3-4 days)
- [ ] Create branch `feature/algorithm-registry`
- [ ] Implement `base.py` with extended AlgorithmInfo
- [ ] Implement `utils.py`
- [ ] Write comprehensive unit tests
- [ ] Document base classes

### Phase 2: Core Registries (4-5 days)
- [ ] Implement `cipher_registry.py` (AES, ChaCha, XChaCha, Fernet, Camellia)
- [ ] Implement `hash_registry.py` (all hashes including BLAKE3, SHAKE, Whirlpool)
- [ ] Implement `kdf_registry.py` (all KDFs including RandomX, Argon2i)
- [ ] Unit tests for all algorithms
- [ ] Integration tests

### Phase 3: PQC Registries (5-6 days)
- [ ] Implement `kem_registry.py` (ML-KEM, HQC)
- [ ] Implement `signature_registry.py` (ML-DSA, FN-DSA, SLH-DSA, MAYO, CROSS)
- [ ] Implement `hybrid_registry.py` (all hybrid modes)
- [ ] Comprehensive PQC tests
- [ ] Known Answer Tests (KATs)

### Phase 4: Integration (3-4 days)
- [ ] Update `cli.py` to use registries
- [ ] Update `config_wizard.py` to use registries
- [ ] Update `template_manager.py` to use registries
- [ ] Update telemetry filters
- [ ] Backward compatibility layer

### Phase 5: Migration & Polish (4-5 days)
- [ ] Migrate `crypt_core.py` to use registries
- [ ] Migrate `identity.py` to use registries
- [ ] Add deprecation warnings
- [ ] Update all documentation
- [ ] Final integration testing
- [ ] Performance benchmarking

**Total Estimated Time: 19-24 days** (3-4 weeks)

---

## Summary of Questions

1. ✅ Branch strategy: Create `feature/algorithm-registry` from `feature/v1.4.0-development`?
2. ✅ Migration approach: Gradual migration with @deprecated warnings?
3. ✅ PQC organization: Separate KEMRegistry, SignatureRegistry, HybridRegistry?
4. ✅ Alias handling: Register both canonical and deprecated names?
5. ✅ Test strategy: Unit + Integration + KAT + Benchmarks?
6. ✅ Security levels: Keep current classification?
7. ✅ Config wizard: Use registry for dynamic algorithm discovery?
8. ✅ Telemetry: Use `registry.allowed_values()` for validation?
9. ✅ Documentation: Generate from registry metadata?
10. ✅ Performance: Add benchmarks to verify no regression?

## Next Steps

Please confirm:
1. Agreement with branching strategy
2. Approval of multi-tier registry architecture (separate registries for PQC)
3. Confirmation that ALL algorithms listed above should be included
4. Any additional requirements or concerns

Once approved, I can begin implementation following the English-language code standard you requested.

---

**End of Analysis**
