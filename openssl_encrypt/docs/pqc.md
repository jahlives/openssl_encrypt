# Post-Quantum Cryptography 

This document explains how to use the post-quantum cryptography features of this tool to protect your data against potential future quantum computer attacks.

## Introduction to Post-Quantum Cryptography

Post-quantum cryptography (PQC) refers to cryptographic algorithms that are believed to be secure against attacks from quantum computers. While current cryptographic standards like RSA and elliptic curve cryptography are secure against classical computers, they are theoretically vulnerable to attacks by sufficiently advanced quantum computers.

This tool integrates quantum-resistant algorithms from the NIST Post-Quantum Cryptography standardization process to provide "quantum-proof" encryption.

## Supported Algorithms

The following post-quantum algorithms are supported:

### Key Encapsulation Mechanisms (KEMs)
- **Kyber-512** - NIST security level 1 (equivalent to AES-128)
- **Kyber-768** - NIST security level 3 (equivalent to AES-192)
- **Kyber-1024** - NIST security level 5 (equivalent to AES-256)

## Installation Requirements

To use post-quantum cryptography features, you'll need to install the liboqs-python package:

```bash
pip install liboqs-python
```

This package provides Python bindings for liboqs, the Open Quantum Safe project's C library implementation of quantum-resistant cryptographic algorithms.

### Manual Installation

as it seems that there is not pypi package atm one need to manually install the required C-Libs and Python bindings
#### Build and install C Libs
```bash
sudo dnf install git gcc cmake ninja-build make golang python3-devel openssl-devel
git clone --recurse-submodules https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install
```
#### Install Python bindings
```bash
pip install --user git+https://github.com/open-quantum-safe/liboqs-python.git
sudo ldconfig
```
If you encounter issues with the installation due to the library not being found, you might need to set the library path explicitly:
```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
```
then test if python can import it
```python
import oqs
print(oqs.get_enabled_kem_mechanisms())
```
## Using Post-Quantum Encryption

### Command Line Usage

You can use post-quantum encryption algorithms directly from the command line:

```bash
python -m openssl_encrypt.crypt encrypt -i file.txt -o file.txt.enc --algorithm kyber768-hybrid
```

The available post-quantum algorithm options are:
- `kyber512-hybrid`
- `kyber768-hybrid`
- `kyber1024-hybrid`

### Recommended Security Levels

- **kyber512-hybrid**: Suitable for encrypting data that requires protection for a few years
- **kyber768-hybrid**: Recommended for most sensitive data (default)
- **kyber1024-hybrid**: Maximum security for highly critical data

## How It Works: Hybrid Encryption

The implementation uses a hybrid approach combining post-quantum and classical cryptography:

1. **Post-Quantum Key Encapsulation**: A post-quantum KEM algorithm (e.g., Kyber) is used to securely establish a shared key
2. **Symmetric Encryption**: The shared key is used with AES-256-GCM to encrypt the actual data
3. **Key Derivation**: Your password is still processed through multiple key derivation functions for additional security

This hybrid approach provides:
- Strong security against both classical and quantum attacks
- Performance benefits compared to using post-quantum algorithms for the entire encryption process
- Compatibility with existing security infrastructure

## Key Management

When using post-quantum encryption, the tool generates and manages both classical and quantum-resistant key pairs. The public key is stored within the encrypted file metadata, while the private key is either:

1. Derived from your password using secure key derivation functions
2. Optionally stored in the file metadata (only when self-decryption is needed)

For maximum security when using post-quantum algorithms, consider using separate key files rather than password-based keys.

## Security Considerations

- Post-quantum cryptography is still an evolving field with ongoing research and standardization efforts
- The implementation follows NIST's recommendations for post-quantum security
- The hybrid approach ensures security even if weaknesses are discovered in either the classical or post-quantum components
- Updates to the post-quantum algorithms will be provided as the standards evolve

## Compatibility

Files encrypted with post-quantum algorithms require the liboqs-python package for decryption. If you're sharing encrypted files, ensure that all parties have the necessary libraries installed.

## Performance Considerations

Post-quantum algorithms generally have larger key sizes and may be computationally more intensive than classical algorithms. Performance impacts include:

- Larger encrypted file sizes due to additional key material
- Slightly slower encryption/decryption operations
- Higher memory usage during cryptographic operations

For most files, these impacts are minimal, but they may be noticeable with very large files.