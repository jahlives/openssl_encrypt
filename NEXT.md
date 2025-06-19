# NEXT: MAYO and CROSS Post-Quantum Signature Implementation Plan

## Executive Summary

This document outlines the implementation of MAYO and CROSS post-quantum signature algorithms in the OpenSSL Encrypt project. Both algorithms are NIST Round 2 candidates offering complementary approaches: MAYO (multivariate-based with compact keys) and CROSS (code-based with small keys but large signatures).

**UPDATE**: Based on analysis of implementation complexity, this plan has been revised to prioritize **liboqs integration** for production-ready implementations while maintaining our demonstration implementations as fallbacks.

## 1. Architecture Overview

### Current State Analysis ✅
- **PQC Module Structure**: Existing `pqc.py`, `pqc_adapter.py`, and `pqc_liboqs.py` modules provide KEM support
- **Integration Points**: `PQCAlgorithm` enum, `ALGORITHM_TYPE_MAP`, and `LIBOQS_ALGORITHM_MAPPING` identified
- **Extension Points**: Signature algorithm support framework already partially defined but not implemented

### Target Architecture (Revised for liboqs)
```
openssl_encrypt/
├── modules/
│   ├── pqc.py                    # Core PQC interface (KEM + Signatures)
│   ├── pqc_adapter.py            # Unified adapter layer
│   ├── pqc_liboqs.py            # ✅ Enhanced LibOQS integration (signatures)
│   ├── pqc_signatures.py        # ✅ Signature interface abstractions
│   ├── mayo_signature.py        # ✅ Demo implementation + liboqs wrapper
│   ├── cross_signature.py       # NEW: CROSS liboqs wrapper + demo fallback
│   └── signature_factory.py     # NEW: Factory for signature instances
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

## 3. REVISED Implementation Strategy: liboqs-First Approach

### Overview
Based on analysis of cryptographic complexity, we're adopting a **production-first approach** using liboqs for actual signature operations while maintaining our demonstration implementations as educational tools and fallbacks.

### Phase 1: Enhanced liboqs Integration ✅ COMPLETED

#### 1.1 Foundation Work (COMPLETED)
- ✅ **PQSignature base class** - Standardized interface for all signature schemes
- ✅ **PQCAlgorithm enum extensions** - Added MAYO and CROSS algorithm constants  
- ✅ **ALGORITHM_TYPE_MAP updates** - Proper algorithm type classification
- ✅ **MAYO demonstration implementation** - Educational implementation showing the interface

### Phase 2: Production liboqs Signature Support

#### 2.1 LibOQS Signature Integration
```python
# Enhanced pqc_liboqs.py
class LibOQSSignature(PQSignature):
    """Production-ready signature implementation using liboqs"""
    
    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        try:
            import oqs
            self.oqs_sig = oqs.Signature(algorithm)
            self.liboqs_available = True
        except (ImportError, RuntimeError) as e:
            self.liboqs_available = False
            self.fallback_reason = str(e)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        if self.liboqs_available:
            public_key = self.oqs_sig.generate_keypair()
            private_key = self.oqs_sig.export_secret_key()
            return public_key, private_key
        else:
            raise RuntimeError(f"liboqs not available: {self.fallback_reason}")
```

#### 2.2 Algorithm Availability Detection
```python
def detect_available_signature_algorithms() -> Dict[str, bool]:
    """Detect which signature algorithms are available in liboqs"""
    available = {}
    
    mayo_candidates = [
        "MAYO-1", "MAYO-3", "MAYO-5",
        "mayo1", "mayo3", "mayo5",  # Alternative naming
    ]
    
    cross_candidates = [
        "CROSS-128", "CROSS-192", "CROSS-256",
        "cross_rsdp_128_balanced", "cross_rsdp_192_balanced", "cross_rsdp_256_balanced"
    ]
    
    try:
        import oqs
        enabled_sigs = oqs.get_enabled_sig_mechanisms()
        
        for candidate in mayo_candidates + cross_candidates:
            available[candidate] = candidate in enabled_sigs
            
    except ImportError:
        # liboqs not available
        for candidate in mayo_candidates + cross_candidates:
            available[candidate] = False
    
    return available
```

### Phase 3: Adaptive Signature Factory

#### 3.1 Signature Factory Implementation
```python
# NEW: signature_factory.py
class SignatureFactory:
    """Factory for creating signature instances with fallback support"""
    
    @staticmethod
    def create_signature(algorithm: str) -> PQSignature:
        """Create signature instance with automatic fallback"""
        
        # 1. Try liboqs first (production implementation)
        if _is_liboqs_available(algorithm):
            return LibOQSSignature(algorithm)
        
        # 2. Fall back to demonstration implementations
        if algorithm.startswith("MAYO"):
            level = _extract_mayo_level(algorithm)
            return MAYOSignature(level)  # Our demo implementation
        elif algorithm.startswith("CROSS"):
            level = _extract_cross_level(algorithm)
            return CROSSSignature(level)  # Future demo implementation
        
        # 3. No implementation available
        raise NotImplementedError(f"No implementation available for {algorithm}")
    
    @staticmethod
    def list_available_algorithms() -> Dict[str, str]:
        """List available algorithms and their implementation source"""
        algorithms = {}
        
        # Check liboqs availability
        liboqs_algos = detect_available_signature_algorithms()
        for algo, available in liboqs_algos.items():
            if available:
                algorithms[algo] = "liboqs (production)"
        
        # Add demo implementations
        algorithms.update({
            "MAYO-1": "demo (educational)",
            "MAYO-3": "demo (educational)",
            "MAYO-5": "demo (educational)",
        })
        
        return algorithms
```

### Phase 4: Enhanced CLI Integration

#### 4.1 Signature Commands with Auto-Detection
```bash
# Enhanced CLI with automatic implementation selection
python -m openssl_encrypt.crypt sign \
  --algorithm mayo-1 \
  --input document.pdf \
  --output document.pdf.sig \
  --private-key private.key
  # Automatically uses liboqs if available, falls back to demo

# List available implementations
python -m openssl_encrypt.crypt list-signature-algorithms
# Output:
# MAYO-1: liboqs (production)
# MAYO-3: demo (educational) 
# CROSS-128: liboqs (production)
```

#### 4.2 Implementation Preference Settings
```python
# Add to crypt_settings.py
class SignatureSettings:
    prefer_liboqs: bool = True
    allow_demo_implementations: bool = True
    require_production_crypto: bool = False  # Strict mode
    
def get_signature_instance(algorithm: str, settings: SignatureSettings) -> PQSignature:
    """Get signature instance respecting user preferences"""
    if settings.require_production_crypto:
        # Only allow liboqs
        return LibOQSSignature(algorithm)
    elif settings.prefer_liboqs:
        # Try liboqs first, fall back to demo
        return SignatureFactory.create_signature(algorithm)
    else:
        # Demo implementations only
        return _create_demo_signature(algorithm)
```

### Phase 5: LibOQS Algorithm Detection and Compatibility

#### 5.1 Runtime Algorithm Discovery
```python
# Enhanced detection for current liboqs versions
def check_mayo_cross_availability() -> Dict[str, Dict]:
    """Check current availability of MAYO and CROSS in liboqs"""
    try:
        import oqs
        available_sigs = oqs.get_enabled_sig_mechanisms()
        
        # Known algorithm names in different liboqs versions
        mayo_variants = {
            "MAYO-1": ["MAYO-1", "mayo1", "MAYO_1"],
            "MAYO-3": ["MAYO-3", "mayo3", "MAYO_3"], 
            "MAYO-5": ["MAYO-5", "mayo5", "MAYO_5"],
        }
        
        cross_variants = {
            "CROSS-128": ["CROSS-128", "cross128", "CROSS_rsdp_128_balanced"],
            "CROSS-192": ["CROSS-192", "cross192", "CROSS_rsdp_192_balanced"],
            "CROSS-256": ["CROSS-256", "cross256", "CROSS_rsdp_256_balanced"],
        }
        
        results = {}
        for standard_name, variants in {**mayo_variants, **cross_variants}.items():
            for variant in variants:
                if variant in available_sigs:
                    results[standard_name] = {
                        "available": True,
                        "liboqs_name": variant,
                        "implementation": "liboqs-production"
                    }
                    break
            else:
                results[standard_name] = {
                    "available": False,
                    "implementation": "demo-fallback"
                }
                
        return results
        
    except ImportError:
        # Return all as unavailable if liboqs not installed
        return {algo: {"available": False, "implementation": "demo-fallback"} 
                for algo in ["MAYO-1", "MAYO-3", "MAYO-5", "CROSS-128", "CROSS-192", "CROSS-256"]}
```

### Phase 6: Production LibOQS Integration

#### 6.1 Enhanced LibOQS Signature Wrapper
```python
# Enhanced pqc_liboqs.py additions
class ProductionSignature(PQSignature):
    """Production signature implementation using liboqs with our interface"""
    
    def __init__(self, algorithm: str):
        self.algorithm = algorithm
        self.availability = check_mayo_cross_availability()
        
        if not self.availability[algorithm]["available"]:
            raise RuntimeError(f"{algorithm} not available in current liboqs installation")
            
        self.liboqs_name = self.availability[algorithm]["liboqs_name"]
        
        import oqs
        self.oqs_signature = oqs.Signature(self.liboqs_name)
    
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate keypair using liboqs production implementation"""
        public_key = self.oqs_signature.generate_keypair()
        private_key = self.oqs_signature.export_secret_key()
        return public_key, private_key
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """Sign using liboqs production implementation"""
        # Import private key into oqs
        temp_sig = oqs.Signature(self.liboqs_name)
        temp_sig.import_secret_key(private_key)
        return temp_sig.sign(message)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify using liboqs production implementation"""
        temp_sig = oqs.Signature(self.liboqs_name)
        return temp_sig.verify(message, signature, public_key)
```

### Phase 7: Unified Testing Strategy

#### 7.1 Cross-Implementation Testing
```python
# tests/test_signature_implementations.py
class TestSignatureImplementations:
    def test_liboqs_vs_demo_compatibility(self):
        """Test that demo and liboqs implementations can interoperate where possible"""
        
    def test_implementation_selection(self):
        """Test SignatureFactory correctly selects implementations"""
        
    def test_graceful_fallback(self):
        """Test fallback from liboqs to demo when liboqs unavailable"""

# tests/test_production_signatures.py  
class TestProductionSignatures:
    @pytest.mark.skipif(not _liboqs_available(), reason="liboqs not available")
    def test_mayo_production_implementation(self):
        """Test MAYO using production liboqs implementation"""
        
    @pytest.mark.skipif(not _liboqs_available(), reason="liboqs not available") 
    def test_cross_production_implementation(self):
        """Test CROSS using production liboqs implementation"""
```

### Phase 8: Enhanced CLI with Implementation Choice

#### 8.1 Enhanced CLI Commands
```bash
# Production-ready CLI commands
python -m openssl_encrypt.crypt sign \
  --algorithm mayo-1 \
  --implementation auto \  # auto, liboqs, demo
  --input document.pdf \
  --output document.pdf.sig \
  --private-key private.key

# Check available implementations
python -m openssl_encrypt.crypt list-signature-algorithms
# Output example:
# MAYO-1: liboqs (production) ✓
# MAYO-3: demo (educational) ⚠
# CROSS-128: liboqs (production) ✓

# Verify implementation compatibility
python -m openssl_encrypt.crypt check-signature-support
```

## 4. REVISED Implementation Timeline (liboqs-First)

### Phase 1: Foundation ✅ COMPLETED (Weeks 1-2)
- ✅ **Signature interfaces designed** - PQSignature base class created
- ✅ **PQC enums extended** - MAYO and CROSS algorithms added
- ✅ **Demo MAYO implementation** - Educational implementation complete

### Phase 2: LibOQS Production Integration ✅ COMPLETED (Weeks 3-4)
- ✅ **LibOQS signature detection** - Runtime algorithm availability checking
- ✅ **ProductionSignature wrapper** - liboqs integration with our interface
- ✅ **SignatureFactory implementation** - Automatic fallback system
- ✅ **Algorithm mapping and compatibility** - Handle different liboqs versions

### Phase 3: Enhanced CLI and Testing (Weeks 5-6)
- [ ] **CLI commands with implementation choice** - Auto-detection and fallback
- [ ] **Cross-implementation testing** - Test liboqs vs demo compatibility
- [ ] **Production test suite** - Tests that require liboqs
- [ ] **Implementation preference settings** - User control over backend choice

### Phase 4: CROSS Integration (Weeks 7-8)  
- [ ] **CROSS liboqs wrapper** - Production CROSS signature support
- [ ] **CROSS demo implementation** - Educational fallback (optional)
- [ ] **Large signature handling** - Efficient CROSS signature processing
- [ ] **Cross-algorithm testing** - MAYO and CROSS together

### Phase 5: Advanced Features (Weeks 9-10)
- [ ] **Keystore signature support** - Store and manage signature keys
- [ ] **Hybrid workflows** - Combine encryption + signatures
- [ ] **Performance optimization** - Benchmark and optimize critical paths
- [ ] **Documentation and guides** - User documentation and migration guides

### Phase 6: Production Readiness (Weeks 11-12)
- [ ] **Security hardening** - Review security practices
- [ ] **Error handling robustness** - Comprehensive error scenarios
- [ ] **Compatibility testing** - Test with different liboqs versions
- [ ] **Deployment preparation** - Package and distribution readiness

## 5. REVISED Risk Assessment and Mitigation (liboqs-First)

### Technical Risks
- **LibOQS Algorithm Availability**: MAYO/CROSS may not be in current liboqs releases
  - *Mitigation*: **Graceful fallback to demo implementations**, runtime detection
- **LibOQS Version Compatibility**: Different liboqs versions may have different algorithm names
  - *Mitigation*: **Multi-variant algorithm detection**, compatibility mapping
- **Performance Impact**: Large CROSS signatures (37-51KB) may impact performance
  - *Mitigation*: **Streaming signature handling**, efficient memory management

### Security Risks  
- **Demo Implementation Security**: Fallback implementations are not cryptographically secure
  - *Mitigation*: **Clear warnings**, force production mode option, user education
- **Mixed Implementation Risk**: Users might accidentally use demo implementations
  - *Mitigation*: **Clear labeling**, require explicit approval for demo usage
- **LibOQS Integration Security**: Wrapper code could introduce vulnerabilities
  - *Mitigation*: **Minimal wrapper design**, defer to liboqs for all crypto operations

### Dependency Risks
- **LibOQS Installation**: Users may not have liboqs installed
  - *Mitigation*: **Optional dependency**, clear installation instructions, CI testing
- **NIST Standardization Changes**: Algorithms may change during standardization  
  - *Mitigation*: **liboqs upstream tracking**, modular design for updates
- **Breaking Changes**: New signature support shouldn't break existing functionality
  - *Mitigation*: **Comprehensive regression testing**, separate signature modules

## 6. REVISED Success Criteria (liboqs-First)

### Functional Requirements
- ✅ **Signature interface foundation** - Unified PQSignature interface
- ✅ **Production signature support** - liboqs-based MAYO and CROSS when available
- ✅ **Graceful fallback system** - Demo implementations when liboqs unavailable
- ✅ **Runtime algorithm detection** - Automatic discovery of available algorithms
- [ ] **CLI signature operations** - Sign, verify, and key generation commands
- ✅ **Implementation transparency** - Clear indication of which backend is used

### Performance Requirements (Production Mode)
- **MAYO signing**: < 10ms for all levels (liboqs optimized)
- **CROSS signing**: < 100ms for all levels (despite large signatures)  
- **Verification**: < 50ms for both algorithms (liboqs optimized)
- **Memory usage**: Efficient handling of large CROSS signatures (37-51KB)

### Security Requirements
- **Production cryptography**: liboqs implementations for actual security
- **Clear implementation labeling**: Users know when using demo vs production
- **Secure fallback handling**: Demo implementations clearly marked as insecure
- **Minimal attack surface**: Thin wrapper around proven liboqs implementations

### Integration Requirements
- **Optional dependency**: Works without liboqs (with warnings)
- **Backward compatibility**: Existing encryption workflows unchanged
- **Modular design**: Signature support cleanly separated from KEM operations
- **User choice**: Explicit control over implementation preference

## 7. Benefits of the LibOQS-First Approach

### Why This Approach is Superior

#### **Production-Ready Security**
- ✅ **Battle-tested implementations** - liboqs has undergone extensive review and testing
- ✅ **Professional cryptographic development** - Implemented by cryptography experts
- ✅ **Regular security updates** - Maintained by Open Quantum Safe consortium
- ✅ **NIST compliance** - Implementations track official NIST specifications

#### **Reduced Development Risk**
- ✅ **Avoid cryptographic implementation errors** - Extremely high risk in crypto development
- ✅ **Faster time to production** - Leverage existing proven implementations
- ✅ **Lower maintenance burden** - Upstream handles algorithm updates and security fixes
- ✅ **Better test coverage** - liboqs has extensive test suites and fuzzing

#### **Future-Proof Architecture**
- ✅ **Algorithm evolution tracking** - liboqs tracks NIST standardization process
- ✅ **Easy algorithm additions** - New signature algorithms automatically available
- ✅ **Performance optimizations** - Benefit from upstream optimizations
- ✅ **Cross-platform support** - liboqs handles platform-specific optimizations

#### **User Benefits**
- ✅ **Confidence in security** - Users can trust production implementations
- ✅ **Performance optimization** - liboqs implementations are highly optimized
- ✅ **Compatibility** - Interoperability with other liboqs-based tools
- ✅ **Educational value** - Demo implementations for learning and experimentation

### Migration Path from Demo to Production

```python
# Phase 1: Demo implementation (COMPLETED)
mayo_demo = MAYOSignature(1)  # Educational/testing only

# Phase 2: Production implementation (PLANNED)
mayo_prod = ProductionSignature("MAYO-1")  # liboqs-based, cryptographically secure

# Phase 3: Automatic selection (PLANNED) 
mayo_auto = SignatureFactory.create_signature("MAYO-1")  # Automatically selects best available
```

## 8. Immediate Next Steps

### Phase 2 ✅ COMPLETED (Weeks 3-4)
1. ✅ **Foundation completed** - PQSignature interface and demo MAYO ready
2. ✅ **LibOQS availability research** - Check current MAYO/CROSS support in liboqs
3. ✅ **ProductionSignature wrapper design** - Create liboqs integration layer
4. ✅ **SignatureFactory implementation** - Build automatic fallback system
5. ✅ **Runtime algorithm detection** - Implement availability checking

### Technical Prerequisites ✅ COMPLETED
- ✅ **LibOQS dependency investigation** - Check which versions support MAYO/CROSS
- ✅ **Development environment setup** - Install and test liboqs with signature support
- ✅ **CI/CD pipeline updates** - Add liboqs testing to build process
- ✅ **Documentation planning** - Prepare user guides for new features

### Validation Steps ✅ COMPLETED
- ✅ **Verify liboqs MAYO support** - Confirm current availability
- ✅ **Test basic liboqs signature operations** - Validate approach feasibility  
- ✅ **Performance baseline establishment** - Measure current capabilities
- ✅ **Compatibility matrix creation** - Document liboqs version requirements

### Phase 3 Next Steps (Enhanced CLI and Testing)
- [ ] **CLI signature commands** - Implement sign, verify, list-algorithms commands
- [ ] **Advanced testing framework** - Cross-implementation compatibility tests  
- [ ] **Performance benchmarking** - Comprehensive algorithm performance analysis
- [ ] **User documentation** - Create guides for signature operations

---

**Document Status**: Phase 2 completed - Production signatures implemented  
**Last Updated**: 2025-06-19  
**Next Review**: Ready for Phase 3 (Enhanced CLI and Testing)

## Phase 2 Achievement Summary ✅

This phase successfully delivered **production-ready MAYO and CROSS signature support** for the OpenSSL Encrypt project:

### Key Deliverables Completed:
- **🏗️ Production Architecture**: liboqs-based signature implementations with automatic fallback
- **🔧 Factory Pattern**: SignatureFactory for seamless implementation selection  
- **🔍 Runtime Detection**: Comprehensive algorithm discovery and compatibility mapping
- **🧪 Test Integration**: 11 signature tests integrated into main test suite
- **📚 Educational Value**: Demo implementations maintain learning opportunities

### Production Capabilities Achieved:
- **MAYO-1, MAYO-2, MAYO-3, MAYO-5**: Multivariate signature support via liboqs
- **CROSS-128, CROSS-192, CROSS-256**: Code-based signature support via liboqs  
- **Stateful Instances**: Work around liboqs API limitations elegantly
- **Automatic Fallback**: Graceful degradation when production implementations unavailable

**Ready for Phase 3**: Enhanced CLI integration and advanced testing framework.