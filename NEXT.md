# NEXT: MAYO and CROSS Post-Quantum Signature Implementation Plan

## Executive Summary

This document outlines the implementation of MAYO and CROSS post-quantum signature algorithms in the OpenSSL Encrypt project. Both algorithms are NIST Round 2 candidates offering complementary approaches: MAYO (multivariate-based with compact keys) and CROSS (code-based with small keys but large signatures).

## 1. Architecture Overview

### Current State Analysis ✅
- **PQC Module Structure**: Existing `pqc.py`, `pqc_adapter.py`, and `pqc_liboqs.py` modules provide KEM support
- **Integration Points**: `PQCAlgorithm` enum, `ALGORITHM_TYPE_MAP`, and `LIBOQS_ALGORITHM_MAPPING` identified
- **Extension Points**: Signature algorithm support framework already partially defined but not implemented

### Target Architecture
```
openssl_encrypt/
├── modules/
│   ├── pqc.py                    # Core PQC interface (KEM + Signatures)
│   ├── pqc_adapter.py            # Unified adapter layer
│   ├── pqc_liboqs.py            # LibOQS integration
│   ├── pqc_signatures.py        # NEW: Signature-specific implementations
│   ├── mayo_signature.py        # NEW: MAYO algorithm implementation
│   └── cross_signature.py       # NEW: CROSS algorithm implementation
```

## 2. Algorithm Specifications

### MAYO (Oil and Vinegar Signature Scheme) ✅
- **Mathematical Foundation**: Multivariate quadratic equations (Oil-and-Vinegar maps)
- **Security Levels**: 
  - MAYO-1: ~128-bit security, 1,168-byte public key, 321-byte signature
  - MAYO-3: ~192-bit security (parameters TBD)
  - MAYO-5: ~256-bit security (parameters TBD)
- **Performance**: Compact public keys, moderate signature sizes
- **NIST Status**: Round 2 candidate (October 2024)

### CROSS (Codes and Restricted Objects Signature Scheme) ✅
- **Mathematical Foundation**: Syndrome decoding with restricted objects
- **Security Levels**:
  - CROSS-128: 61-byte public key, 16-byte private key, ~37KB signature
  - CROSS-192: 91-byte public key, 24-byte private key, ~37KB signature  
  - CROSS-256: 121-byte public key, 32-byte private key, ~51KB signature
- **Performance**: Very small keys, very large signatures
- **NIST Status**: Round 2 candidate (October 2024)

## 3. Implementation Strategy

### Phase 1: Core Signature Interface Design

#### 3.1 PQC Algorithm Enum Extensions
```python
# In pqc.py - extend PQCAlgorithm enum
class PQCAlgorithm(Enum):
    # ... existing KEM algorithms ...
    
    # MAYO Signature Algorithms
    MAYO_1 = "MAYO-1"           # Level 1 (128-bit security)
    MAYO_3 = "MAYO-3"           # Level 3 (192-bit security) 
    MAYO_5 = "MAYO-5"           # Level 5 (256-bit security)
    
    # CROSS Signature Algorithms  
    CROSS_128 = "CROSS-128"     # Level 1 (128-bit security)
    CROSS_192 = "CROSS-192"     # Level 3 (192-bit security)
    CROSS_256 = "CROSS-256"     # Level 5 (256-bit security)
```

#### 3.2 Signature Interface Design
```python
# NEW: pqc_signatures.py
class PQSignature:
    """Base class for post-quantum signature schemes"""
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate (public_key, private_key) pair"""
        raise NotImplementedError
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign message with private key"""
        raise NotImplementedError
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature against message and public key"""
        raise NotImplementedError
    
    def get_algorithm_name(self) -> str:
        """Return algorithm identifier"""
        raise NotImplementedError
```

### Phase 2: MAYO Implementation

#### 3.3 MAYO Algorithm Implementation
```python
# NEW: mayo_signature.py
class MAYOSignature(PQSignature):
    """MAYO (Oil-and-Vinegar) signature implementation"""
    
    def __init__(self, security_level: int = 1):
        self.security_level = security_level
        self.params = self._get_parameters(security_level)
    
    def _get_parameters(self, level: int) -> Dict:
        """Get MAYO parameters for security level"""
        params = {
            1: {  # MAYO-1 (NIST Level 1)
                'n': 81, 'm': 64, 'o': 17, 'k': 4, 'q': 16,
                'public_key_size': 1168,
                'signature_size': 321,
                'private_key_size': 32  # seed size
            },
            3: {  # MAYO-3 (NIST Level 3) - estimated
                'n': 108, 'm': 85, 'o': 23, 'k': 5, 'q': 16,
                'public_key_size': 2400,
                'signature_size': 520,
                'private_key_size': 48
            },
            5: {  # MAYO-5 (NIST Level 5) - estimated
                'n': 135, 'm': 106, 'o': 29, 'k': 6, 'q': 16,
                'public_key_size': 4200,
                'signature_size': 750,
                'private_key_size': 64
            }
        }
        return params.get(level, params[1])
```

### Phase 3: CROSS Implementation

#### 3.4 CROSS Algorithm Implementation
```python
# NEW: cross_signature.py
class CROSSSignature(PQSignature):
    """CROSS (Syndrome Decoding) signature implementation"""
    
    def __init__(self, security_level: int = 128):
        self.security_level = security_level
        self.params = self._get_parameters(security_level)
    
    def _get_parameters(self, level: int) -> Dict:
        """Get CROSS parameters for security level"""
        params = {
            128: {  # CROSS-128 (NIST Level 1)
                'public_key_size': 61,
                'private_key_size': 16,
                'signature_size': 37080,
                'field_size': 256  # GF(2^8)
            },
            192: {  # CROSS-192 (NIST Level 3)
                'public_key_size': 91,
                'private_key_size': 24,
                'signature_size': 37080,
                'field_size': 256
            },
            256: {  # CROSS-256 (NIST Level 5)
                'public_key_size': 121,
                'private_key_size': 32,
                'signature_size': 51120,
                'field_size': 256
            }
        }
        return params.get(level, params[128])
```

### Phase 4: Integration with Existing System

#### 3.5 PQC Adapter Extensions
```python
# Update pqc_adapter.py
ALGORITHM_TYPE_MAP.update({
    # MAYO Signature Algorithms
    "MAYO-1": "sig",
    "MAYO-3": "sig", 
    "MAYO-5": "sig",
    # CROSS Signature Algorithms
    "CROSS-128": "sig",
    "CROSS-192": "sig",
    "CROSS-256": "sig",
})

SECURITY_LEVEL_MAP.update({
    # MAYO algorithms
    "MAYO-1": 1,
    "MAYO-3": 3,
    "MAYO-5": 5,
    # CROSS algorithms  
    "CROSS-128": 1,
    "CROSS-192": 3,
    "CROSS-256": 5,
})
```

#### 3.6 LibOQS Integration
```python
# Update pqc_liboqs.py
LIBOQS_ALGORITHM_MAPPING.update({
    # MAYO signatures (if supported by liboqs)
    "MAYO-1": "MAYO_1",
    "MAYO-3": "MAYO_3", 
    "MAYO-5": "MAYO_5",
    # CROSS signatures
    "CROSS-128": "CROSS_rsdp_128_balanced",
    "CROSS-192": "CROSS_rsdp_192_balanced",
    "CROSS-256": "CROSS_rsdp_256_balanced",
})
```

### Phase 5: CLI Interface Extensions

#### 3.7 Command Line Interface
```bash
# New signature operations
python -m openssl_encrypt.crypt sign \
  --algorithm mayo-1 \
  --input document.pdf \
  --output document.pdf.sig \
  --private-key private.key

python -m openssl_encrypt.crypt verify \
  --algorithm mayo-1 \
  --input document.pdf \
  --signature document.pdf.sig \
  --public-key public.key

# Key generation
python -m openssl_encrypt.crypt keygen \
  --algorithm cross-128 \
  --output-public public.key \
  --output-private private.key
```

#### 3.8 CLI Module Extensions
```python
# Update cli.py
def add_signature_commands(parser):
    """Add signature-related commands to CLI"""
    sig_parser = parser.add_subparser('sign', help='Sign data')
    sig_parser.add_argument('--algorithm', choices=[
        'mayo-1', 'mayo-3', 'mayo-5',
        'cross-128', 'cross-192', 'cross-256'
    ])
    
    verify_parser = parser.add_subparser('verify', help='Verify signature')
    # ... similar arguments
    
    keygen_parser = parser.add_subparser('keygen', help='Generate key pair')
    # ... key generation arguments
```

### Phase 6: Keystore Integration

#### 3.9 Keystore Extensions
```python
# Update pqc_keystore.py
class PQCKeystore:
    def store_signature_keypair(self, algorithm: str, public_key: bytes, 
                              private_key: bytes, alias: str):
        """Store signature key pair in keystore"""
        
    def get_signing_key(self, alias: str) -> bytes:
        """Retrieve private signing key"""
        
    def get_verification_key(self, alias: str) -> bytes:
        """Retrieve public verification key"""
        
    def list_signature_keys(self) -> List[Dict]:
        """List all signature keys in keystore"""
```

### Phase 7: Testing Strategy

#### 3.10 Unit Tests
```python
# tests/test_mayo_signature.py
class TestMAYOSignature:
    def test_keypair_generation(self):
        """Test MAYO key pair generation"""
        
    def test_sign_verify_round_trip(self):
        """Test sign/verify round trip"""
        
    def test_signature_sizes(self):
        """Test signature and key sizes match specifications"""
        
    def test_security_levels(self):
        """Test all security levels (1, 3, 5)"""

# tests/test_cross_signature.py  
class TestCROSSSignature:
    def test_keypair_generation(self):
        """Test CROSS key pair generation"""
        
    def test_sign_verify_round_trip(self):
        """Test sign/verify round trip"""
        
    def test_large_signature_handling(self):
        """Test handling of large CROSS signatures"""
```

#### 3.11 Integration Tests
```python
# tests/test_signature_integration.py
class TestSignatureIntegration:
    def test_cli_sign_verify_workflow(self):
        """Test complete CLI workflow"""
        
    def test_keystore_integration(self):
        """Test keystore signature key management"""
        
    def test_hybrid_encryption_with_signatures(self):
        """Test combining encryption with signatures"""
```

### Phase 8: Documentation and Migration

#### 3.12 Documentation Updates
- **Algorithm Reference**: Add MAYO and CROSS to algorithm-reference.md
- **User Guide**: Add signature operation examples
- **Security Guide**: Document signature algorithm security properties
- **Migration Guide**: How to adopt signature algorithms

#### 3.13 Migration Strategy
1. **Backward Compatibility**: Ensure existing KEM operations unchanged
2. **Gradual Rollout**: Optional signature features initially
3. **Performance Testing**: Benchmark signature operations
4. **Security Audit**: Third-party review of implementations

## 4. Implementation Timeline

### Phase 1: Foundation (Weeks 1-2)
- [ ] Design signature interfaces
- [ ] Extend PQC enums and mappings
- [ ] Create base signature classes

### Phase 2: MAYO Implementation (Weeks 3-4)
- [ ] Implement MAYO parameter sets
- [ ] Core signing/verification logic
- [ ] Unit tests for MAYO

### Phase 3: CROSS Implementation (Weeks 5-6)
- [ ] Implement CROSS parameter sets  
- [ ] Handle large signature sizes efficiently
- [ ] Unit tests for CROSS

### Phase 4: Integration (Weeks 7-8)
- [ ] CLI interface extensions
- [ ] Keystore integration
- [ ] Integration testing

### Phase 5: Testing & Documentation (Weeks 9-10)
- [ ] Comprehensive testing
- [ ] Performance benchmarking
- [ ] Documentation updates
- [ ] Security review

## 5. Risk Assessment and Mitigation

### Technical Risks
- **Algorithm Complexity**: MAYO and CROSS are mathematically complex
  - *Mitigation*: Reference implementations, extensive testing
- **Performance Impact**: Large CROSS signatures may impact performance
  - *Mitigation*: Streaming signature handling, compression options
- **LibOQS Dependencies**: Algorithms may not be available in liboqs
  - *Mitigation*: Implement native fallbacks, check availability

### Security Risks
- **Implementation Vulnerabilities**: Side-channel attacks, timing attacks
  - *Mitigation*: Constant-time operations, security audit
- **Parameter Validation**: Incorrect parameters could compromise security
  - *Mitigation*: Thorough parameter validation, test vectors

### Compatibility Risks
- **NIST Standardization Changes**: Algorithms may change during standardization
  - *Mitigation*: Modular design for easy parameter updates
- **Breaking Changes**: New algorithms shouldn't break existing functionality
  - *Mitigation*: Comprehensive regression testing

## 6. Success Criteria

### Functional Requirements
- ✅ Generate MAYO/CROSS key pairs for all security levels
- ✅ Sign and verify messages with correct algorithms
- ✅ CLI interface supports signature operations
- ✅ Keystore manages signature keys securely
- ✅ Integration with existing encryption workflows

### Performance Requirements
- MAYO signing: < 50ms for Level 1, < 100ms for Level 5
- CROSS signing: < 500ms for all levels (due to large signatures)
- Verification: < 100ms for both algorithms
- Memory usage: < 1GB even with large CROSS signatures

### Security Requirements
- Constant-time operations for sensitive computations
- Secure memory handling for private keys
- Resistance to known attacks on signature schemes
- Compliance with NIST security level definitions

## 7. Next Steps

1. **Review and Approval**: Get stakeholder approval for this implementation plan
2. **Resource Allocation**: Assign developers and time for each phase
3. **Reference Research**: Gather MAYO and CROSS reference implementations
4. **Development Environment**: Set up development and testing environments
5. **Phase 1 Kickoff**: Begin with signature interface design

---

**Document Status**: Draft  
**Last Updated**: 2025-06-19  
**Next Review**: After Phase 1 completion

This comprehensive implementation plan provides a roadmap for successfully integrating MAYO and CROSS post-quantum signature algorithms into the OpenSSL Encrypt project, maintaining security, performance, and usability standards while preparing for the post-quantum cryptographic future.