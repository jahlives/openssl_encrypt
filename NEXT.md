# NEXT: MAYO and CROSS Post-Quantum Hybrid Encryption Implementation Plan

## Executive Summary

This document outlines the implementation of MAYO and CROSS post-quantum algorithms as **hybrid encryption methods** in the OpenSSL Encrypt project. Both algorithms are NIST Round 2 candidates that will be integrated using the same hybrid encryption pattern as ML-KEM and HQC.

**UPDATE**: Based on project focus clarification, MAYO and CROSS will be implemented as **encryption algorithms** (not signature algorithms) following the established hybrid encryption workflow: password → KDF → master key (A), generate private key (B), encrypt file with B, encrypt B with A, store encrypted B in metadata.

## 1. Architecture Overview

### Current State Analysis ✅
- **PQC Module Structure**: Existing `pqc.py`, `pqc_adapter.py`, and `pqc_liboqs.py` modules provide KEM/hybrid encryption support
- **Integration Points**: `PQCAlgorithm` enum, `ALGORITHM_TYPE_MAP`, and `LIBOQS_ALGORITHM_MAPPING` identified
- **Extension Points**: Signature algorithms already registered but need hybrid encryption implementation
- **Hybrid Pattern**: ML-KEM and HQC provide the exact template for MAYO and CROSS implementation

### Target Architecture (Hybrid Encryption Focus)
```
openssl_encrypt/
├── modules/
│   ├── pqc.py                    # Core PQC interface (KEM + Hybrid Encryption)
│   ├── pqc_adapter.py            # ✅ Unified adapter layer (add MAYO/CROSS mappings)
│   ├── pqc_liboqs.py            # ✅ Enhanced LibOQS integration (add MAYO/CROSS)
│   ├── crypt_core.py            # ✅ Main encryption workflow (add MAYO/CROSS enum values)
│   └── pqc_keystore.py          # ✅ Secure key storage (already supports hybrid encryption)
```

## 2. Algorithm Specifications

### MAYO (Oil and Vinegar) - Hybrid Encryption ✅
- **Mathematical Foundation**: Multivariate quadratic equations (Oil-and-Vinegar maps)
- **Security Levels**: 
  - MAYO-1: ~128-bit security, 32-byte private key (compatible with AES-256)
  - MAYO-3: ~192-bit security, 48-byte private key (requires key derivation)
  - MAYO-5: ~256-bit security, 64-byte private key (compatible with AES-SIV)
- **Encryption Usage**: Private keys used as encryption secrets via key derivation
- **NIST Status**: Round 2 candidate (October 2024)

### CROSS (Codes and Restricted Objects) - Hybrid Encryption ✅
- **Mathematical Foundation**: Syndrome decoding with restricted objects
- **Security Levels**:
  - CROSS-128: 128-bit security, 16-byte private key (requires key derivation)
  - CROSS-192: 192-bit security, 24-byte private key (requires key derivation)  
  - CROSS-256: 256-bit security, 32-byte private key (compatible with AES-256)
- **Encryption Usage**: Private keys used as encryption secrets via key derivation
- **NIST Status**: Round 2 candidate (October 2024)

## 3. REVISED Implementation Strategy: Hybrid Encryption Approach

### Overview
Based on project focus clarification, we're implementing MAYO and CROSS as **hybrid encryption algorithms** following the exact same pattern as ML-KEM and HQC. This approach uses signature algorithm private keys as encryption secrets through secure key derivation, maintaining the established encryption-focused workflow.

### Phase 1: Foundation Work ✅ COMPLETED

#### 1.1 Algorithm Registration (COMPLETED)
- ✅ **PQCAlgorithm enum extensions** - Added MAYO and CROSS algorithm constants in `pqc.py`
- ✅ **ALGORITHM_TYPE_MAP updates** - Proper algorithm type classification in `pqc_adapter.py`
- ✅ **LIBOQS_ALGORITHM_MAPPING** - Algorithm name mappings in `pqc_liboqs.py`
- ✅ **CLI signature support** - Basic signature operations implemented

### Phase 2: Hybrid Encryption Implementation

#### 2.1 Hybrid Encryption Pattern (Following ML-KEM/HQC)
```python
# Pattern: Password → KDF → Master Key (A)
# Generate PQ Private Key (B) → Use B as encryption secret
# Encrypt file with derived key from B
# Encrypt B with A → Store in metadata as C

# Add to crypt_core.py EncryptionAlgorithm enum:
MAYO_1_HYBRID = "mayo-1-hybrid"
MAYO_3_HYBRID = "mayo-3-hybrid" 
MAYO_5_HYBRID = "mayo-5-hybrid"
CROSS_128_HYBRID = "cross-128-hybrid"
CROSS_192_HYBRID = "cross-192-hybrid"
CROSS_256_HYBRID = "cross-256-hybrid"
```

#### 2.2 Algorithm Mapping Integration
```python
# Add to pqc_adapter.py HYBRID_ALGORITHM_MAP:
"mayo-1-hybrid": "MAYO-1",
"mayo-3-hybrid": "MAYO-3", 
"mayo-5-hybrid": "MAYO-5",
"cross-128-hybrid": "CROSS-128",
"cross-192-hybrid": "CROSS-192",
"cross-256-hybrid": "CROSS-256",

# Add to pqc_adapter.py SECURITY_LEVEL_MAP:
"MAYO-1": 1,      # Level 1 (128-bit security)
"MAYO-3": 3,      # Level 3 (192-bit security)
"MAYO-5": 5,      # Level 5 (256-bit security)
"CROSS-128": 1,   # Level 1 (128-bit security)
"CROSS-192": 3,   # Level 3 (192-bit security)
"CROSS-256": 5,   # Level 5 (256-bit security)
```

#### 2.3 Decryption Integration
```python
# Add to crypt_core.py decrypt_file function:
# PQC algorithm list (around line 3249)
EncryptionAlgorithm.MAYO_1_HYBRID.value,
EncryptionAlgorithm.MAYO_3_HYBRID.value,
EncryptionAlgorithm.MAYO_5_HYBRID.value,
EncryptionAlgorithm.CROSS_128_HYBRID.value,
EncryptionAlgorithm.CROSS_192_HYBRID.value,
EncryptionAlgorithm.CROSS_256_HYBRID.value,

# PQC algorithm mapping (around line 3267)
EncryptionAlgorithm.MAYO_1_HYBRID.value: "MAYO-1",
EncryptionAlgorithm.MAYO_3_HYBRID.value: "MAYO-3", 
EncryptionAlgorithm.MAYO_5_HYBRID.value: "MAYO-5",
EncryptionAlgorithm.CROSS_128_HYBRID.value: "CROSS-128",
EncryptionAlgorithm.CROSS_192_HYBRID.value: "CROSS-192",
EncryptionAlgorithm.CROSS_256_HYBRID.value: "CROSS-256",
```

## 4. Hybrid Encryption Workflow (Identical to ML-KEM/HQC)

### Encryption Process:
1. **Password Processing**: User password → Scrypt/Argon2/PBKDF2 → Master Key (A)
2. **Key Generation**: Generate MAYO/CROSS keypair via liboqs → Private Key (B)
3. **Key Derivation**: Derive encryption key from B using HKDF → Symmetric Key (D)
4. **File Encryption**: Encrypt file content using D with AES-GCM/ChaCha20
5. **Key Protection**: Encrypt B with A using AES-GCM → Encrypted Key (C)
6. **Metadata Storage**: Store C, public key, and salt in file metadata

### Decryption Process:
1. **Password Processing**: User password + stored salt → Recreate Master Key (A)
2. **Key Recovery**: Decrypt C with A → Recover Private Key (B)
3. **Key Derivation**: Derive encryption key from B using HKDF → Symmetric Key (D)
4. **File Decryption**: Decrypt file content using D

### Key Sizes and Compatibility:
```python
# Key derivation ensures compatibility with all encryption algorithms
def derive_encryption_key(mayo_cross_private_key: bytes, algorithm: str) -> bytes:
    """
    Derive symmetric encryption key from MAYO/CROSS private key
    
    Compatible with all implemented algorithms:
    - 32-byte keys: AES-GCM, ChaCha20-Poly1305, Fernet, etc.
    - 64-byte keys: AES-SIV
    """
    salt = b"OpenSSL-Encrypt-PQ-Hybrid-Encryption"
    info = f"encryption-key-{algorithm}".encode()
    
    # Determine target key size based on algorithm
    target_size = 64 if algorithm == "aes-siv" else 32
    
    return HKDF(
        algorithm=hashes.SHA256(),
        length=target_size,
        salt=salt,
        info=info,
    ).derive(mayo_cross_private_key)
```

## 5. Implementation Timeline

### Phase 1: Foundation ✅ COMPLETED
- ✅ **Algorithm registration** - All constants and mappings in place
- ✅ **LibOQS integration** - MAYO and CROSS available via liboqs
- ✅ **CLI signature support** - Basic operations implemented

### Phase 2: Hybrid Encryption Integration (Current Priority)
- [ ] **EncryptionAlgorithm enum** - Add 6 new hybrid algorithm constants
- [ ] **Algorithm mappings** - Add hybrid mappings to `pqc_adapter.py` 
- [ ] **Decryption integration** - Add algorithms to `crypt_core.py` decrypt function
- [ ] **CLI integration** - Enable hybrid encryption via command line

### Phase 3: Testing and Validation 
- [ ] **End-to-end testing** - Test encryption/decryption workflow
- [ ] **Key derivation testing** - Validate key compatibility across algorithms
- [ ] **Performance benchmarking** - Compare with ML-KEM/HQC performance
- [ ] **Integration testing** - Test with existing encryption algorithms

### Phase 4: Documentation and Finalization
- [ ] **User documentation** - Update guides for new algorithms
- [ ] **CLI help updates** - Add MAYO/CROSS to help text
- [ ] **Security documentation** - Document key derivation security properties
- [ ] **Performance documentation** - Benchmark results and recommendations

## 6. Implementation Requirements

### Required File Modifications:

#### `crypt_core.py` (2 locations)
1. **EncryptionAlgorithm enum** - Add 6 new algorithm constants
2. **decrypt_file function** - Add algorithms to PQC detection and mapping

#### `pqc_adapter.py` (2 locations)  
1. **HYBRID_ALGORITHM_MAP** - Add 6 new hybrid mappings
2. **SECURITY_LEVEL_MAP** - Add 6 new security level mappings

#### No other files require modification
- ✅ `pqc.py` - Already contains algorithm constants
- ✅ `pqc_liboqs.py` - Already contains liboqs mappings
- ✅ `pqc_keystore.py` - Already supports hybrid encryption pattern
- ✅ All other modules work without changes

## 7. Success Criteria

### Functional Requirements
- [ ] **Encryption compatibility** - All 6 algorithms encrypt/decrypt successfully
- [ ] **Key derivation** - All key sizes work with all encryption algorithms
- [ ] **Metadata integration** - Proper storage and retrieval of encrypted keys
- [ ] **CLI integration** - Command-line access to all hybrid algorithms

### Performance Requirements
- **Key generation**: < 100ms for all MAYO/CROSS variants
- **Encryption**: Comparable to ML-KEM/HQC hybrid performance
- **Decryption**: < 50ms overhead for key derivation
- **Memory usage**: Efficient handling of larger MAYO keys

### Security Requirements  
- **Key separation**: Different encryption algorithms get different derived keys
- **Forward security**: Compromise of one key doesn't affect others
- **Post-quantum security**: Maintain PQ properties through key derivation
- **Metadata security**: Encrypted private keys properly protected

## 8. Benefits of Hybrid Encryption Approach

### Security Benefits
- **Unified key management** - Single MAYO/CROSS key enables both signing and encryption
- **Post-quantum encryption** - Quantum-resistant encryption using PQ key material
- **Key derivation security** - Cryptographically independent keys per algorithm
- **Future-proof** - Easy addition of new encryption algorithms

### Operational Benefits
- **Consistent interface** - Same workflow as existing ML-KEM/HQC algorithms
- **Reduced complexity** - No new metadata formats or storage mechanisms
- **Backward compatibility** - Existing encryption workflows unchanged
- **User familiarity** - Same command-line interface patterns

### Technical Benefits
- **Proven pattern** - Leverages tested ML-KEM/HQC implementation
- **Minimal code changes** - Only 4 locations need modification
- **Automatic compatibility** - Works with all 18 existing encryption algorithms
- **Extensible design** - Easy to add more signature-based hybrid algorithms

## 9. Next Steps (Phase 2 Implementation)

### Immediate Tasks:
1. **Add EncryptionAlgorithm constants** - 6 new enum values in `crypt_core.py`
2. **Add hybrid mappings** - 6 entries in `pqc_adapter.py` HYBRID_ALGORITHM_MAP
3. **Add security mappings** - 6 entries in `pqc_adapter.py` SECURITY_LEVEL_MAP  
4. **Add decryption support** - 6 entries in `crypt_core.py` decrypt function

### Testing Tasks:
1. **Basic functionality** - Test encrypt/decrypt for all 6 algorithms
2. **Key compatibility** - Test with AES-GCM, ChaCha20, AES-SIV
3. **CLI integration** - Test command-line usage
4. **Performance validation** - Benchmark against ML-KEM/HQC

### Expected Timeline: 1-2 weeks
- **Week 1**: Implementation of 4 required code changes
- **Week 2**: Testing, validation, and documentation updates

---

**Document Status**: Phase 1 completed - Ready for Phase 2 hybrid encryption implementation  
**Last Updated**: 2025-06-19  
**Next Review**: After Phase 2 implementation completion

## Phase 1 Achievement Summary ✅

Algorithm registration and CLI signature support successfully completed:

### Key Deliverables Completed:
- **🔧 Algorithm Constants**: MAYO and CROSS added to `pqc.py` PQCAlgorithm enum
- **🗺️ Type Mappings**: Algorithm classification added to `pqc_adapter.py` ALGORITHM_TYPE_MAP
- **🔗 LibOQS Integration**: Algorithm name mappings added to `pqc_liboqs.py` LIBOQS_ALGORITHM_MAPPING
- **🖥️ CLI Support**: Full command-line signature operations (sign, verify, generate-keys, list-algorithms)

### Production Capabilities Achieved:
- **MAYO-1, MAYO-3, MAYO-5**: Multivariate signature support via liboqs
- **CROSS-128, CROSS-192, CROSS-256**: Code-based signature support via liboqs  
- **Signature Factory**: Automatic implementation selection (production/demo)
- **CLI Integration**: Complete command-line interface for signature operations

**Ready for Phase 2**: Hybrid encryption implementation following ML-KEM/HQC pattern.