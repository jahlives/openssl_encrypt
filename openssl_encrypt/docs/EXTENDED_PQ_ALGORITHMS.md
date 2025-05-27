# Extended Post-Quantum Algorithm Support

This document describes the implementation of additional post-quantum cryptographic algorithms beyond our native ML-KEM (formerly Kyber) implementation. These additional algorithms provide greater diversity and options for post-quantum security.

## Overview

The implementation adds support for several additional post-quantum algorithms through integration with the Open Quantum Safe (OQS) library via its Python bindings (`liboqs-python`). This allows our application to leverage a wider range of post-quantum algorithms while maintaining compatibility with our existing architecture.

## Algorithms Added

### Key Encapsulation Mechanisms (KEMs)

- **HQC (Hamming Quasi-Cyclic)** - Selected by NIST in March 2025 as an additional KEM algorithm
  - HQC-128 (Security Level 1, equivalent to AES-128)
  - HQC-192 (Security Level 3, equivalent to AES-192)
  - HQC-256 (Security Level 5, equivalent to AES-256)

### Digital Signature Algorithms (DSAs)

- **ML-DSA (formerly Dilithium)** - NIST FIPS 204
  - ML-DSA-44 (Security Level 1)
  - ML-DSA-65 (Security Level 3)
  - ML-DSA-87 (Security Level 5)

- **SLH-DSA (formerly SPHINCS+)** - NIST FIPS 205
  - SLH-DSA-SHA2-128F (Security Level 1)
  - SLH-DSA-SHA2-192F (Security Level 3)
  - SLH-DSA-SHA2-256F (Security Level 5)

- **FN-DSA (formerly Falcon)** - NIST FIPS 206
  - FN-DSA-512 (Security Level 1)
  - FN-DSA-1024 (Security Level 5)

## Hybrid Modes

For backward compatibility and added security, all new KEMs are implemented in hybrid mode, combining post-quantum algorithms with traditional symmetric encryption:

- `hqc-128-hybrid`
- `hqc-192-hybrid`
- `hqc-256-hybrid`

Additionally, new hybrid modes with different symmetric algorithms are available:

- `ml-kem-512-chacha20` (ML-KEM-512 with ChaCha20-Poly1305)
- `ml-kem-768-chacha20` (ML-KEM-768 with ChaCha20-Poly1305)
- `ml-kem-1024-chacha20` (ML-KEM-1024 with ChaCha20-Poly1305)

## Implementation Details

### Architecture

The implementation follows a modular approach:

1. **Core Wrapper (`pqc_liboqs.py`)**
   - Provides direct wrappers for liboqs algorithms
   - Handles availability detection and algorithm mapping
   - Separates KEM and signature algorithm implementations

2. **Adapter Layer (`pqc_adapter.py`)**
   - Extends our native `PQCipher` class
   - Provides unified interface for both native and liboqs algorithms
   - Transparently routes operations to appropriate implementation

3. **CLI Integration (`crypt_cli_helper.py`)**
   - Extends CLI with support for new algorithms
   - Provides appropriate defaults while respecting user choices
   - Adds help text for new algorithms

### Graceful Degradation

The implementation handles missing dependencies gracefully:

- If `liboqs-python` is not installed, the code falls back to our native ML-KEM implementation
- Informative error messages guide users on how to install missing dependencies
- All new algorithms are clearly marked in CLI help with appropriate guidance

### User Choice Preservation

The implementation preserves user choice:

- Users can still select their preferred symmetric encryption algorithm via CLI options
- The `--encryption-data` parameter is respected for all algorithms
- Default values are sensibly chosen based on algorithm type

## Security Considerations

- All new algorithms maintain our existing security standards
- Security levels are clearly documented (Level 1, 3, 5)
- Hybrid modes protect against potential weaknesses in either classical or post-quantum algorithms
- Implementation follows best practices from NIST and industry standards

## Future Work

- Add more comprehensive documentation for new algorithms
- Create migration guides for users of existing algorithms
- Implement performance benchmarking for all algorithms
- Consider additional hybrid modes with different symmetric algorithms

## References

- NIST Post-Quantum Cryptography Standardization: https://csrc.nist.gov/Projects/post-quantum-cryptography
- Open Quantum Safe Project: https://openquantumsafe.org/
- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/ipd
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/ipd
- NIST FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/ipd
- NIST FIPS 206 (FN-DSA): https://csrc.nist.gov/pubs/fips/206/ipd