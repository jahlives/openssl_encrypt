# Post-Quantum Cryptography Mobile Implementation Requirements

## 🎯 Executive Summary

This document outlines the requirements and approach for implementing Post-Quantum Cryptography (PQC) support in the OpenSSL Encrypt mobile application. The CLI implementation uses a **hybrid approach** where PQC algorithms are used for key encapsulation/exchange, while symmetric algorithms handle the actual data encryption.

**Reference Documentation**: This analysis is based on the official CLI documentation in `/docs/algorithm-reference.md`, `/docs/security.md`, and `/docs/metadata-formats.md`.

## 📋 Current CLI PQC Implementation Analysis

### Hybrid Encryption Architecture

The CLI uses a sophisticated hybrid approach:

1. **Key Generation**: Generate/use PQC keypair (public + private key)
2. **Symmetric Key Generation**: Generate random symmetric key (32 bytes for AES-256-GCM)
3. **Data Encryption**: Encrypt data with symmetric algorithm (AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, etc.)
4. **Key Encapsulation**: Encrypt symmetric key using PQC public key (KEM encapsulation)
5. **Storage**: Store both encrypted data and encapsulated key in a single format

### Supported PQC Algorithms (from official docs)

#### NIST Standardized Algorithms (FIPS 203-206)
| Algorithm | NIST Standard | Security Level | Status | Key Size | Ciphertext Size |
|-----------|---------------|----------------|--------|----------|-----------------|
| **ML-KEM-512** | FIPS 203 | Level 1 (AES-128 equiv) | ✅ Implemented | 1.6KB | 0.8KB |
| **ML-KEM-768** | FIPS 203 | Level 3 (AES-192 equiv) | ✅ Implemented | 2.4KB | 1.2KB |
| **ML-KEM-1024** | FIPS 203 | Level 5 (AES-256 equiv) | ✅ Implemented | 3.2KB | 1.6KB |

#### Additional NIST Algorithms (via liboqs)
| Algorithm | Status | Security Level | Key Size | Ciphertext Size |
|-----------|--------|----------------|----------|-----------------|
| **HQC-128** | Pending NIST (2026) | Level 1 | 2.4KB | 4.8KB |
| **HQC-192** | Pending NIST (2026) | Level 3 | 4.8KB | 9.6KB |
| **HQC-256** | Pending NIST (2026) | Level 5 | 7.2KB | 14.4KB |
| **MAYO-1/3/5** | NIST Round 2 | Signature algorithms | Variable | Variable |
| **CROSS-128/192/256** | NIST Round 2 | Signature algorithms | Variable | Variable |

#### Official Hybrid Combinations (from algorithm-reference.md)
**ML-KEM Hybrid Modes:**
- `ml-kem-512-hybrid`: ML-KEM-512 + AES-GCM
- `ml-kem-768-hybrid`: ML-KEM-768 + AES-GCM (**recommended**)
- `ml-kem-1024-hybrid`: ML-KEM-1024 + AES-GCM
- `ml-kem-512-chacha20`: ML-KEM-512 + ChaCha20-Poly1305
- `ml-kem-768-chacha20`: ML-KEM-768 + ChaCha20-Poly1305
- `ml-kem-1024-chacha20`: ML-KEM-1024 + ChaCha20-Poly1305

**HQC Hybrid Modes:**
- `hqc-128-hybrid`: HQC-128 + AES-GCM
- `hqc-192-hybrid`: HQC-192 + AES-GCM
- `hqc-256-hybrid`: HQC-256 + AES-GCM
- Plus ChaCha20-Poly1305 variants

### File Format Structure

#### Metadata Structure (JSON, Base64-encoded)
```json
{
  "format_version": 5,
  "derivation_config": {
    "salt": "base64_salt",
    "hash_config": {...},
    "kdf_config": {...}
  },
  "encryption": {
    "algorithm": "ml-kem-1024-hybrid",
    "encryption_data": "aes-gcm",
    "pqc_public_key": "base64_encoded_public_key",
    "pqc_private_key": "base64_encoded_encrypted_private_key",
    "pqc_key_salt": "base64_key_salt",
    "pqc_key_encrypted": true
  },
  "hashes": {
    "original_hash": "sha256_of_original_data",
    "encrypted_hash": "sha256_of_encrypted_data"
  }
}
```

#### Encrypted Data Format
- **Binary data containing**: `encapsulated_key + symmetric_encrypted_data`
- **encapsulated_key**: Result of PQC KEM encapsulation (variable size)
- **symmetric_encrypted_data**: Result of AES-GCM/ChaCha20/etc. encryption

## 🔧 Technical Dependencies

### Primary Dependency: liboqs-python (from official user-guide.md)

**Package**: `liboqs-python>=0.7.0`

The CLI provides **two installation methods** for PQC support:

#### Method 1: Standard Installation (Recommended)
```bash
pip install liboqs-python
```

#### Method 2: Manual Installation (if PyPI unavailable)
```bash
# Step 1: Install system dependencies
sudo dnf install git gcc cmake ninja-build make golang python3-devel openssl-devel
# (or apt-get for Ubuntu/Debian)

# Step 2: Build liboqs C library
git clone --recurse-submodules https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja && sudo ninja install

# Step 3: Install Python bindings
pip install --user git+https://github.com/open-quantum-safe/liboqs-python.git
sudo ldconfig

# Step 4: Verify installation
python -c "import oqs; print(oqs.get_enabled_kem_mechanisms())"
```

#### liboqs Python Interface
The CLI implementation relies heavily on the **Open Quantum Safe (OQS) liboqs** library via its Python wrapper:

```python
import oqs

# Key Encapsulation Mechanism
kem = oqs.KeyEncapsulation("ML-KEM-1024")
public_key, private_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encap_secret(public_key)
recovered_secret = kem.decap_secret(ciphertext)

# Digital Signatures
sig = oqs.Signature("ML-DSA-65")
public_key, private_key = sig.generate_keypair()
signature = sig.sign(message)
is_valid = sig.verify(message, signature, public_key)
```

### Architecture Modules

The CLI implementation consists of several key modules:

1. **`modules/pqc.py`** - Core PQC implementation and algorithm management
2. **`modules/pqc_adapter.py`** - Abstraction layer between native and liboqs algorithms
3. **`modules/pqc_liboqs.py`** - Direct liboqs integration and wrapper classes
4. **`modules/crypt_core.py`** - Integration with main encryption system

## 📱 Mobile Implementation Challenges

### 1. Python Dependency Management

**Challenge**: Mobile environments don't typically support full Python package management.

**Solutions**:
- **Option A**: Bundle pre-compiled liboqs binaries with the mobile app
- **Option B**: Use native mobile PQC libraries (platform-specific)
- **Option C**: Implement PQC algorithms natively in Dart/Flutter
- **Option D**: Server-side PQC operations (hybrid approach)

### 2. Platform-Specific Considerations

#### iOS Challenges
- **App Store restrictions** on cryptographic libraries
- **Code signing** requirements for embedded binaries
- **Size constraints** (liboqs is a large library)
- **Performance** concerns on older devices

#### Android Challenges
- **NDK integration** for native libraries
- **Multiple architectures** (arm64-v8a, armeabi-v7a, x86_64)
- **API level compatibility** across different Android versions
- **Memory constraints** on lower-end devices

### 3. Library Size and Performance

**liboqs Library Stats**:
- **Size**: ~10-50MB depending on algorithms included
- **Memory usage**: Varies by algorithm (ML-KEM: ~1MB, signatures: more)
- **Performance**: Computationally intensive, especially key generation

**Mobile Optimization Needed**:
- Algorithm subset selection (only include needed algorithms)
- Lazy loading of algorithms
- Memory pool management
- Background processing for key generation

## 🚀 Implementation Strategy Options

### Option 1: Native liboqs Integration (Most Compatible)

**Approach**: Bundle liboqs with the mobile app and use Python subprocess calls.

**Pros**:
- ✅ **Full compatibility** with CLI implementation
- ✅ **All algorithms supported**
- ✅ **Minimal code changes** needed
- ✅ **Proven stability** (same code as CLI)

**Cons**:
- ❌ **Large app size** increase (~20-50MB)
- ❌ **Platform-specific compilation** complexity
- ❌ **Python runtime dependency**
- ❌ **Potential app store approval issues**

**Implementation**:
```python
# Add to mobile_crypto_core.py
try:
    import oqs
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False

def encrypt_pqc_hybrid(self, data, password, algorithm, public_key=None):
    if not PQC_AVAILABLE:
        raise ImportError("PQC not available - install liboqs-python")

    # 1. Generate symmetric key
    symmetric_key = os.urandom(32)

    # 2. Encrypt data with symmetric algorithm
    if algorithm.endswith('-aes-gcm'):
        encrypted_data = self.encrypt_aes_gcm(data, symmetric_key)
    elif algorithm.endswith('-chacha20'):
        encrypted_data = self.encrypt_chacha20(data, symmetric_key)

    # 3. Encapsulate symmetric key with PQC
    pqc_algorithm = algorithm.split('-hybrid')[0].upper()
    kem = oqs.KeyEncapsulation(pqc_algorithm)
    if not public_key:
        public_key, private_key = kem.generate_keypair()

    encapsulated_key, _ = kem.encap_secret(public_key)

    # 4. Combine formats
    return encapsulated_key + encrypted_data
```

### Option 2: Platform-Native PQC Libraries (Best Performance)

**Approach**: Use native iOS/Android PQC implementations.

**iOS**: Use Apple's CryptoKit or third-party Swift libraries
**Android**: Use native C++ libraries via NDK

**Pros**:
- ✅ **Best performance** and memory usage
- ✅ **Small app size** impact
- ✅ **Platform optimization**
- ✅ **No Python dependency**

**Cons**:
- ❌ **Limited algorithm support** (mostly ML-KEM/Kyber only)
- ❌ **Platform-specific code** maintenance
- ❌ **Potential compatibility issues** with CLI
- ❌ **Complex testing** and validation

### Option 3: Hybrid Server-Client Approach (Most Practical)

**Approach**: Handle PQC operations server-side, maintain symmetric encryption client-side.

**Flow**:
1. Mobile generates symmetric key
2. Mobile encrypts data with symmetric algorithm
3. Server handles PQC key encapsulation/decapsulation
4. Mobile stores/retrieves encapsulated keys from server

**Pros**:
- ✅ **Small mobile footprint**
- ✅ **Full algorithm support**
- ✅ **Easy updates** (server-side)
- ✅ **Cross-platform consistency**

**Cons**:
- ❌ **Network dependency**
- ❌ **Server infrastructure** requirements
- ❌ **Privacy concerns** (keys transmitted to server)
- ❌ **Offline usage** not possible

### Option 4: Selective Algorithm Implementation (Recommended)

**Approach**: Implement only essential PQC algorithms natively, with graceful fallbacks.

**Priority Algorithms**:
1. **ML-KEM-1024** (most important, NIST standard)
2. **ML-KEM-768** (balance of security/performance)
3. **ML-DSA-65** (signatures, if needed)

**Implementation Strategy**:
- Use existing Dart/Flutter crypto libraries where possible
- Implement missing algorithms using well-tested reference implementations
- Maintain CLI format compatibility for supported algorithms
- Graceful degradation for unsupported algorithms

## 📊 Resource Requirements Analysis

### Development Resources
- **Senior Mobile Developer**: 3-4 weeks (Option 1 or 4)
- **Cryptography Specialist**: 2-3 weeks (algorithm implementation)
- **DevOps Engineer**: 1-2 weeks (build system, testing)
- **QA Testing**: 2-3 weeks (compatibility testing)

### Testing Requirements
- **Unit tests** for each PQC algorithm
- **Integration tests** with CLI compatibility
- **Performance tests** on various devices
- **Memory usage analysis**
- **Battery impact assessment**

### App Size Impact
- **Option 1 (liboqs)**: +20-50MB
- **Option 2 (native)**: +5-10MB
- **Option 3 (server)**: +1-2MB
- **Option 4 (selective)**: +10-20MB

## 🎯 Recommended Implementation Plan

### Phase 1: Foundation (2 weeks)
1. **Analyze current symmetric implementation** - Ensure AES-GCM, ChaCha20-Poly1305 work perfectly
2. **Design PQC abstraction layer** - Create interface for PQC operations
3. **Set up testing framework** - CLI compatibility test suite
4. **Prototype evaluation** - Test different approach options

### Phase 2: Core Implementation (3 weeks)
1. **Implement ML-KEM-1024 support** (highest priority)
   - Key generation
   - Encapsulation/decapsulation
   - Format compatibility with CLI
2. **Add hybrid encryption logic**
   - Combine PQC + symmetric encryption
   - Metadata handling
   - Error handling and fallbacks
3. **CLI compatibility testing**

### Phase 3: Extended Support (2 weeks)
1. **Add ML-KEM-768 support**
2. **Implement additional symmetric algorithms** (if needed)
3. **Performance optimization**
4. **Memory usage optimization**

### Phase 4: Testing & Validation (2 weeks)
1. **Comprehensive CLI compatibility testing**
2. **Performance benchmarking**
3. **Security audit**
4. **Documentation**

## ⚠️ Security Considerations (from official documentation)

### PQC-Specific Security (from security.md)

**Mathematical Diversity Protection**:
- **ML-KEM**: Based on module lattice problems (Ring-LWE)
- **HQC**: Based on error-correcting codes (syndrome decoding)
- This diversity provides protection against potential breakthroughs in either mathematical approach

**When to Use Post-Quantum Encryption** (official guidelines):
- Data that must remain confidential for 10+ years
- Information subject to "harvest now, decrypt later" attacks
- Highly sensitive data requiring maximum security

**Hybrid Security Model**:
> "All post-quantum encryption uses hybrid encryption combining:
> 1. **Classical Encryption**: AES-GCM or ChaCha20-Poly1305 for data encryption
> 2. **Post-Quantum Key Encapsulation**: ML-KEM (Kyber) or HQC for key protection
>
> This ensures data remains secure even if either classical or quantum algorithms are compromised."

### Implementation Security Requirements
- **Private key protection** - Ensure proper secure storage
- **Memory management** - Clear sensitive data from memory
- **Random number generation** - Use cryptographically secure RNG
- **Side-channel protections** - Following CLI security model

### Algorithm Selection Guidelines (from algorithm-reference.md)
- **Prefer NIST-standardized algorithms** (ML-KEM-768 recommended)
- **Use standardized names** (ml-kem-* vs deprecated kyber* names)
- **Mathematical foundation diversity** for maximum protection

## 📋 Success Criteria

### Functional Requirements
- ✅ **CLI Compatibility**: Mobile can decrypt CLI PQC-encrypted files
- ✅ **Algorithm Support**: At least ML-KEM-1024 and ML-KEM-768
- ✅ **Format Compatibility**: Proper metadata and format handling
- ✅ **Error Handling**: Graceful fallbacks when PQC unavailable

### Performance Requirements
- ✅ **Key Generation**: < 2 seconds for ML-KEM-1024
- ✅ **Encryption/Decryption**: < 1 second for typical file sizes
- ✅ **Memory Usage**: < 50MB additional memory usage
- ✅ **App Size**: < 25MB additional app size

### Quality Requirements
- ✅ **Test Coverage**: > 90% code coverage for PQC modules
- ✅ **CLI Compatibility**: 100% compatibility with supported algorithms
- ✅ **Cross-Platform**: iOS and Android support
- ✅ **Documentation**: Complete API and user documentation

## 🎉 Conclusion

Post-quantum cryptography support for mobile is **technically feasible** but requires careful consideration of trade-offs between **compatibility**, **performance**, and **implementation complexity**.

**Recommended approach**: Start with **Option 4 (Selective Algorithm Implementation)** focusing on ML-KEM-1024, with a clear path to expand support based on user needs and technical constraints.

The existing mobile symmetric encryption foundation is solid, making PQC integration a natural evolution rather than a complete redesign.

---
*Document prepared for OpenSSL Encrypt Mobile PQC Integration - 2025-08-09*
