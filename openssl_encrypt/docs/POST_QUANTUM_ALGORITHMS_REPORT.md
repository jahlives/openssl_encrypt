# Post-Quantum Cryptography Algorithm Report

This document presents an analysis of newer post-quantum cryptographic algorithms that could enhance our library's capabilities beyond the current ML-KEM (formerly Kyber) implementation.

## Current Status of NIST PQC Standardization

As of May 2025, NIST has standardized several post-quantum algorithms:

1. **ML-KEM** (FIPS 203, formerly CRYSTALS-Kyber) - Key Encapsulation Mechanism based on module lattices
2. **ML-DSA** (FIPS 204, formerly CRYSTALS-Dilithium) - Digital Signature Algorithm based on module lattices
3. **SLH-DSA** (FIPS 205, formerly SPHINCS+) - Digital Signature Algorithm based on hash functions

NIST is still finalizing:
- **FN-DSA** (FIPS 206, formerly Falcon) - Digital Signature Algorithm based on NTRU lattices
- **HQC** (future standard, announced March 2025) - Key Encapsulation Mechanism based on error-correcting codes

## Algorithm Analysis and Implementation Considerations

### 1. HQC (Hamming Quasi-Cyclic)

**Mathematical Foundation:** Error-correcting codes, specifically Quasi-Cyclic codes

**Selected by NIST:** March 11, 2025

**Purpose:** Backup KEM to ML-KEM, using a different mathematical approach (code-based vs lattice-based)

**Key Characteristics:**
- Based on error-correcting codes, which have decades of usage in information security
- Longer and more resource-intensive than ML-KEM, but provides diversification from lattice-based cryptography
- Expected draft standard in 2026, final standard in 2027

**Implementation Considerations:**
- Implementation would require expertise in code-based cryptography
- Available in liboqs through the Open Quantum Safe (OQS) project
- Python bindings available through liboqs-python

**Recommendation:** Implement as a backup KEM to provide algorithmic diversity against potential lattice-based vulnerabilities.

### 2. ML-DSA (Module Lattice-based Digital Signature Algorithm)

**Mathematical Foundation:** Module lattices (same as ML-KEM)

**Purpose:** Primary standard for digital signatures (FIPS 204)

**Key Characteristics:**
- Considered the most viable general-purpose post-quantum signature scheme
- Relatively light on CPU usage
- Large signatures and public keys (2.4KB and 1.3KB respectively at Level 1)
- Adds approximately 14.7KB to a TLS handshake

**Implementation Considerations:**
- Shares mathematical foundations with ML-KEM, allowing code reuse
- New domain-separated signatures for hash-then-sign operations
- Available in liboqs through OQS
- Pure Python implementation available via "dilithium-py"

**Recommendation:** High priority implementation as the primary NIST-standardized signature algorithm.

### 3. SLH-DSA (Stateless Hash-based Digital Signature Algorithm)

**Mathematical Foundation:** Hash functions

**Purpose:** Backup signature algorithm to ML-DSA (FIPS 205)

**Key Characteristics:**
- Based entirely on hash functions, making its security well-understood
- Larger overhead than ML-DSA (approximately 39KB added to transactions)
- Significant computational overhead for both signing and verification
- Security reliance solely on hash functions provides diversification

**Implementation Considerations:**
- Implementation is relatively straightforward since it relies only on hash functions
- Hash-then-sign variant named HashSLH-DSA in the specification
- Context string parameter added to sign and verify functions
- No backward compatibility due to signature context string addition

**Recommendation:** Medium priority implementation as a backup signature algorithm.

### 4. FN-DSA (FFT NTRU-lattice-based Digital Signature Algorithm)

**Mathematical Foundation:** NTRU lattices with Fast Fourier Transform techniques

**Purpose:** Alternative signature algorithm, focusing on compactness (FIPS 206 forthcoming)

**Key Characteristics:**
- Extremely strong security and high bandwidth efficiency
- Faster verification than ML-DSA and SLH-DSA
- Very compact signatures
- Challenging secure implementation due to floating-point arithmetic requirements

**Implementation Considerations:**
- Requires fast floating-point arithmetic, which is difficult to implement securely
- Signing can be performed with emulated floating-point arithmetic, but is much slower
- Verification is simple and doesn't require floating-point arithmetic
- Missing a middle security level between Falcon-512 and Falcon-1024

**Recommendation:** Lower priority implementation due to implementation challenges, but valuable for applications where signature size is critical.

## Implementation Approach

### 1. Python Library Dependencies

The most practical approach for implementing these algorithms is to leverage the liboqs library and its Python bindings:

```python
# Example of importing liboqs-python
from oqs import KeyEncapsulation, Signature

# For HQC
kem = KeyEncapsulation("HQC-128")
public_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encapsulate(public_key)
decapsulated_secret = kem.decapsulate(ciphertext)

# For ML-DSA
sig = Signature("ML-DSA-65")
public_key, secret_key = sig.generate_keypair()
signature = sig.sign(message, secret_key)
is_valid = sig.verify(message, signature, public_key)
```

### 2. Integration with Existing Architecture

To integrate these new algorithms into our current architecture:

1. **Create Adapter Classes**: Create adapter classes for each algorithm that conform to our existing interfaces
2. **Extend EncryptionAlgorithm Enum**: Add new algorithm options to the EncryptionAlgorithm enum
3. **Implement Hybrid Modes**: Support hybrid classical/post-quantum modes for all new algorithms
4. **Deprecation Handling**: Ensure all new algorithms work with our deprecation warning system

### 3. Implementation Prioritization

Based on the analysis, the recommended implementation order is:

1. **ML-DSA**: Highest priority as the primary NIST-standardized signature algorithm
2. **HQC**: High priority as a backup KEM using different mathematical principles
3. **SLH-DSA**: Medium priority as a backup signature algorithm
4. **FN-DSA**: Lower priority due to implementation challenges

## Security Levels and Parameters

For each algorithm, we should implement multiple security levels to provide flexibility:

1. **Level 1**: Equivalent to AES-128 (ML-KEM-512, ML-DSA-44, SLH-DSA-SHA2-128F, FN-DSA-512, HQC-128)
2. **Level 3**: Equivalent to AES-192 (ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-192F, HQC-192)
3. **Level 5**: Equivalent to AES-256 (ML-KEM-1024, ML-DSA-87, SLH-DSA-SHA2-256F, FN-DSA-1024, HQC-256)

## Testing and Validation

To ensure correctness and security of implementations:

1. **Known Answer Tests (KATs)**: Implement tests using known input/output pairs from NIST
2. **Interoperability Tests**: Test against other implementations (liboqs, BouncyCastle, etc.)
3. **Performance Benchmarks**: Measure key generation, encapsulation/signing, and decapsulation/verification times
4. **Side-Channel Resistance**: Ensure constant-time implementations where possible

## Conclusion and Recommendations

The post-quantum cryptography landscape continues to evolve, with NIST standardizing multiple algorithms based on different mathematical foundations. Our library would benefit significantly from implementing these algorithms, particularly:

1. **HQC** for a backup KEM using a different mathematical approach than ML-KEM
2. **ML-DSA** for a standardized digital signature algorithm
3. **SLH-DSA** and **FN-DSA** to provide signature algorithm alternatives

Implementation should leverage the liboqs library and its Python bindings while ensuring proper integration with our existing architecture and security practices.

The recommended next step is to begin with ML-DSA implementation, followed by HQC, as these provide the most immediate value in expanding our post-quantum capabilities.