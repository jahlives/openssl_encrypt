# Threefish-512 Implementation Plan

*Für Claude Code zur Implementierung*

---

## Übersicht

Integration von Threefish-512 als "Paranoia Mode" Cipher für echte 256-bit Post-Quantum-Sicherheit.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Post-Quantum Sicherheit                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Cipher              Key-Bits    Grover Halbierung    PQ-Sicherheit    │
│  ─────────────────────────────────────────────────────────────────────  │
│  AES-256             256         → 128-bit            Ausreichend       │
│  ChaCha20            256         → 128-bit            Ausreichend       │
│  Threefish-512       512         → 256-bit            Maximum ✅        │
│  Threefish-1024      1024        → 512-bit            Overkill          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Architektur

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Build Time                                  │
│                           (GitLab CI/CD)                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────┐  │
│  │ Rust Source     │    │ Maturin         │    │ Platform Wheels     │  │
│  │                 │    │                 │    │                     │  │
│  │ • threefish     │───▶│ • Cross-compile │───▶│ • manylinux x86_64  │  │
│  │ • pyo3          │    │ • Bundle        │    │ • macos x86_64      │  │
│  │ • poly1305      │    │                 │    │ • macos arm64       │  │
│  │                 │    │                 │    │ • windows amd64     │  │
│  └─────────────────┘    └─────────────────┘    └─────────────────────┘  │
│                                                         │               │
└─────────────────────────────────────────────────────────┼───────────────┘
                                                          │
                                                          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                             Runtime                                      │
│                         (User System)                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  pip install openssl-encrypt[threefish]                                 │
│                    │                                                    │
│                    ▼                                                    │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ openssl_encrypt                                                  │   │
│  │                                                                  │   │
│  │  ┌──────────────────┐   ┌──────────────────┐                    │   │
│  │  │ crypt_core.py    │   │ threefish_native │ ← Compiled Rust    │   │
│  │  │                  │   │                  │                    │   │
│  │  │ --cipher aes-gcm │   │ encrypt_aead()   │                    │   │
│  │  │ --cipher chacha  │   │ decrypt_aead()   │                    │   │
│  │  │ --cipher tf512 ──│──▶│                  │                    │   │
│  │  │ --cipher cascade │   │                  │                    │   │
│  │  └──────────────────┘   └──────────────────┘                    │   │
│  │                                                                  │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Teil 1: Projektstruktur

### 1.1 Repository-Struktur

```
openssl_encrypt/
├── openssl_encrypt/           # Bestehender Python-Code
│   ├── modules/
│   │   ├── crypt_core.py
│   │   ├── cipher_registry.py    # NEU: Cipher-Abstraktion
│   │   └── ...
│   └── ...
│
├── threefish_native/             # NEU: Rust Extension
│   ├── Cargo.toml
│   ├── pyproject.toml
│   ├── src/
│   │   ├── lib.rs               # PyO3 Bindings
│   │   ├── threefish_aead.rs    # Threefish-512-CTR + Poly1305
│   │   └── error.rs             # Error Types
│   ├── tests/
│   │   └── test_vectors.rs
│   └── benches/
│       └── benchmark.rs
│
├── pyproject.toml               # Haupt-Projekt mit optional dependency
└── .gitlab-ci.yml               # Build Pipeline
```

### 1.2 Optional Dependency Setup

**Datei:** `pyproject.toml` (Haupt-Projekt)

```toml
[project]
name = "openssl-encrypt"
version = "1.4.0"
# ...

[project.optional-dependencies]
threefish = ["openssl-encrypt-threefish>=1.0.0"]
paranoia = ["openssl-encrypt-threefish>=1.0.0"]  # Alias

[project.entry-points."openssl_encrypt.ciphers"]
threefish-512 = "openssl_encrypt.ciphers.threefish:Threefish512Cipher"
```

---

## Teil 2: Rust Implementation

### 2.1 Cargo.toml

**Datei:** `threefish_native/Cargo.toml`

```toml
[package]
name = "openssl-encrypt-threefish"
version = "1.0.0"
edition = "2021"
authors = ["OpenSSL Encrypt Team"]
description = "Threefish-512 AEAD cipher for openssl-encrypt"
license = "MIT"
repository = "https://github.com/..."

[lib]
name = "threefish_native"
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.20", features = ["extension-module"] }
threefish = "0.5"
poly1305 = "0.8"
subtle = "2.5"           # Constant-time operations
zeroize = { version = "1.7", features = ["zeroize_derive"] }
rand = "0.8"

[dev-dependencies]
hex = "0.4"
criterion = "0.5"

[profile.release]
lto = true              # Link-time optimization
codegen-units = 1       # Bessere Optimierung
strip = true            # Debug-Symbole entfernen

[[bench]]
name = "benchmark"
harness = false
```

### 2.2 PyO3 Bindings

**Datei:** `threefish_native/src/lib.rs`

```rust
//! Threefish-512 AEAD Python Bindings
//!
//! Bietet Threefish-512 in CTR-Mode mit Poly1305 Authentication.
//! Ermöglicht echte 256-bit Post-Quantum-Sicherheit.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyBytes;
use zeroize::Zeroize;

mod threefish_aead;
mod error;

use threefish_aead::Threefish512Aead;

/// Threefish-512 AEAD Encryption
///
/// Args:
///     key: 64 bytes (512 bits)
///     nonce: 32 bytes (256 bits) - Threefish Tweak
///     plaintext: Data to encrypt
///     associated_data: Optional AAD for authentication
///
/// Returns:
///     ciphertext + 16-byte Poly1305 tag
#[pyfunction]
fn encrypt(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Py<PyBytes>> {
    // Validate inputs
    if key.len() != 64 {
        return Err(PyValueError::new_err(
            format!("Key must be 64 bytes (512 bits), got {}", key.len())
        ));
    }
    if nonce.len() != 32 {
        return Err(PyValueError::new_err(
            format!("Nonce must be 32 bytes (256 bits), got {}", nonce.len())
        ));
    }

    let aad = associated_data.unwrap_or(&[]);
    
    let cipher = Threefish512Aead::new(key)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    
    let ciphertext = cipher.encrypt(nonce, plaintext, aad)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    
    Ok(PyBytes::new(py, &ciphertext).into())
}


/// Threefish-512 AEAD Decryption
///
/// Args:
///     key: 64 bytes (512 bits)
///     nonce: 32 bytes (256 bits)
///     ciphertext: Encrypted data + 16-byte tag
///     associated_data: Optional AAD (must match encryption)
///
/// Returns:
///     Decrypted plaintext
///
/// Raises:
///     ValueError: Invalid key/nonce size
///     RuntimeError: Authentication failed (tampered data)
#[pyfunction]
fn decrypt(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Py<PyBytes>> {
    // Validate inputs
    if key.len() != 64 {
        return Err(PyValueError::new_err(
            format!("Key must be 64 bytes (512 bits), got {}", key.len())
        ));
    }
    if nonce.len() != 32 {
        return Err(PyValueError::new_err(
            format!("Nonce must be 32 bytes (256 bits), got {}", nonce.len())
        ));
    }
    if ciphertext.len() < 16 {
        return Err(PyValueError::new_err(
            "Ciphertext too short (must include 16-byte tag)"
        ));
    }

    let aad = associated_data.unwrap_or(&[]);
    
    let cipher = Threefish512Aead::new(key)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    
    let plaintext = cipher.decrypt(nonce, ciphertext, aad)
        .map_err(|_| PyRuntimeError::new_err(
            "Authentication failed: data may be corrupted or tampered"
        ))?;
    
    Ok(PyBytes::new(py, &plaintext).into())
}


/// Generate a random 64-byte key
#[pyfunction]
fn generate_key(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    use rand::RngCore;
    let mut key = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut key);
    let result = PyBytes::new(py, &key).into();
    key.zeroize();
    Ok(result)
}


/// Generate a random 32-byte nonce
#[pyfunction]
fn generate_nonce(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    Ok(PyBytes::new(py, &nonce).into())
}


/// Get algorithm info
#[pyfunction]
fn algorithm_info() -> PyResult<&'static str> {
    Ok("Threefish-512-CTR with Poly1305 authentication (512-bit key, 256-bit PQ security)")
}


/// Python module definition
#[pymodule]
fn threefish_native(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(generate_nonce, m)?)?;
    m.add_function(wrap_pyfunction!(algorithm_info, m)?)?;
    
    // Constants
    m.add("KEY_SIZE", 64)?;
    m.add("NONCE_SIZE", 32)?;
    m.add("TAG_SIZE", 16)?;
    m.add("VERSION", "1.0.0")?;
    
    Ok(())
}
```

### 2.3 Threefish AEAD Implementation

**Datei:** `threefish_native/src/threefish_aead.rs`

```rust
//! Threefish-512 AEAD: CTR Mode + Poly1305 Authentication
//!
//! Da Threefish kein eingebautes AEAD hat, bauen wir es selbst:
//! - Threefish-512 im CTR-Mode für Verschlüsselung
//! - Poly1305 für Authentication (wie bei ChaCha20-Poly1305)
//!
//! Format: ciphertext || poly1305_tag (16 bytes)

use threefish::Threefish512;
use poly1305::{Poly1305, universal_hash::UniversalHash};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Block size for Threefish-512
const BLOCK_SIZE: usize = 64;

/// Poly1305 tag size
const TAG_SIZE: usize = 16;

/// Error type
#[derive(Debug)]
pub enum AeadError {
    InvalidKeyLength,
    InvalidNonceLength,
    AuthenticationFailed,
    EncryptionFailed,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "Invalid key length (need 64 bytes)"),
            Self::InvalidNonceLength => write!(f, "Invalid nonce length (need 32 bytes)"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
        }
    }
}

/// Threefish-512 AEAD Cipher
#[derive(ZeroizeOnDrop)]
pub struct Threefish512Aead {
    #[zeroize(skip)]  // Threefish handles its own cleanup
    cipher: Threefish512,
    #[zeroize]
    key: [u8; 64],
}

impl Threefish512Aead {
    /// Create new AEAD instance
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 64 {
            return Err(AeadError::InvalidKeyLength);
        }
        
        let mut key_arr = [0u8; 64];
        key_arr.copy_from_slice(key);
        
        // Threefish needs key + tweak, we use first half of nonce as tweak later
        let tweak = [0u64; 2];  // Will be set per-operation
        let cipher = Threefish512::new_with_tweak(&key_arr, &tweak);
        
        Ok(Self {
            cipher,
            key: key_arr,
        })
    }
    
    /// Encrypt plaintext with authentication
    ///
    /// Returns: ciphertext || tag (16 bytes)
    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 32 {
            return Err(AeadError::InvalidNonceLength);
        }
        
        // Derive tweak from first 16 bytes of nonce
        let tweak = self.nonce_to_tweak(nonce);
        
        // CTR encryption
        let ciphertext = self.ctr_encrypt(plaintext, nonce, &tweak)?;
        
        // Derive Poly1305 key from Threefish (encrypt zero block)
        let poly_key = self.derive_poly_key(nonce, &tweak)?;
        
        // Compute authentication tag
        let tag = self.compute_tag(&poly_key, &ciphertext, aad);
        
        // Combine: ciphertext || tag
        let mut result = ciphertext;
        result.extend_from_slice(&tag);
        
        Ok(result)
    }
    
    /// Decrypt ciphertext with authentication
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext_with_tag: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 32 {
            return Err(AeadError::InvalidNonceLength);
        }
        if ciphertext_with_tag.len() < TAG_SIZE {
            return Err(AeadError::AuthenticationFailed);
        }
        
        // Split ciphertext and tag
        let (ciphertext, tag) = ciphertext_with_tag.split_at(
            ciphertext_with_tag.len() - TAG_SIZE
        );
        
        // Derive tweak and poly key
        let tweak = self.nonce_to_tweak(nonce);
        let poly_key = self.derive_poly_key(nonce, &tweak)?;
        
        // Verify tag (constant time!)
        let expected_tag = self.compute_tag(&poly_key, ciphertext, aad);
        if bool::from(expected_tag.ct_eq(tag)) == false {
            return Err(AeadError::AuthenticationFailed);
        }
        
        // Decrypt
        let plaintext = self.ctr_decrypt(ciphertext, nonce, &tweak)?;
        
        Ok(plaintext)
    }
    
    /// Convert nonce to Threefish tweak
    fn nonce_to_tweak(&self, nonce: &[u8]) -> [u64; 2] {
        let mut tweak = [0u64; 2];
        tweak[0] = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        tweak[1] = u64::from_le_bytes(nonce[8..16].try_into().unwrap());
        tweak
    }
    
    /// CTR mode encryption
    fn ctr_encrypt(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        tweak: &[u64; 2],
    ) -> Result<Vec<u8>, AeadError> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let cipher = Threefish512::new_with_tweak(&self.key, tweak);
        
        // Use second half of nonce as counter base
        let mut counter = [0u8; BLOCK_SIZE];
        counter[..16].copy_from_slice(&nonce[16..32]);
        
        for (block_idx, chunk) in plaintext.chunks(BLOCK_SIZE).enumerate() {
            // Set counter
            let block_num = (block_idx as u64).to_le_bytes();
            counter[16..24].copy_from_slice(&block_num);
            
            // Encrypt counter block
            let mut keystream = counter.clone();
            cipher.encrypt_block(&mut keystream);
            
            // XOR with plaintext
            for (i, byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream[i]);
            }
        }
        
        Ok(ciphertext)
    }
    
    /// CTR mode decryption (same as encryption)
    fn ctr_decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        tweak: &[u64; 2],
    ) -> Result<Vec<u8>, AeadError> {
        // CTR mode is symmetric
        self.ctr_encrypt(ciphertext, nonce, tweak)
    }
    
    /// Derive Poly1305 key by encrypting zeros
    fn derive_poly_key(
        &self,
        nonce: &[u8],
        tweak: &[u64; 2],
    ) -> Result<[u8; 32], AeadError> {
        let cipher = Threefish512::new_with_tweak(&self.key, tweak);
        
        // Use nonce as input, get first 32 bytes of output as Poly1305 key
        let mut block = [0u8; BLOCK_SIZE];
        block[..32].copy_from_slice(nonce);
        block[32] = 0xFF;  // Domain separator
        
        cipher.encrypt_block(&mut block);
        
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&block[..32]);
        
        block.zeroize();
        
        Ok(poly_key)
    }
    
    /// Compute Poly1305 authentication tag
    fn compute_tag(
        &self,
        poly_key: &[u8; 32],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> [u8; TAG_SIZE] {
        use poly1305::Key;
        
        let key = Key::from_slice(poly_key);
        let mut mac = Poly1305::new(key);
        
        // Authenticate: AAD || pad || ciphertext || pad || len(AAD) || len(CT)
        // (Similar to ChaCha20-Poly1305 construction)
        
        // AAD
        mac.update_padded(aad);
        
        // Ciphertext
        mac.update_padded(ciphertext);
        
        // Lengths (8 bytes each, little-endian)
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        mac.update(&len_block);
        
        mac.finalize().into_bytes().into()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_roundtrip() {
        let key = [0x42u8; 64];
        let nonce = [0x24u8; 32];
        let plaintext = b"Hello, Threefish-512!";
        let aad = b"additional data";
        
        let cipher = Threefish512Aead::new(&key).unwrap();
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
    
    #[test]
    fn test_tampered_ciphertext() {
        let key = [0x42u8; 64];
        let nonce = [0x24u8; 32];
        let plaintext = b"Hello, Threefish-512!";
        
        let cipher = Threefish512Aead::new(&key).unwrap();
        
        let mut ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        
        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;
        
        let result = cipher.decrypt(&nonce, &ciphertext, &[]);
        assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
    }
    
    #[test]
    fn test_tampered_tag() {
        let key = [0x42u8; 64];
        let nonce = [0x24u8; 32];
        let plaintext = b"Hello, Threefish-512!";
        
        let cipher = Threefish512Aead::new(&key).unwrap();
        
        let mut ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();
        
        // Tamper with tag (last 16 bytes)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;
        
        let result = cipher.decrypt(&nonce, &ciphertext, &[]);
        assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
    }
    
    #[test]
    fn test_wrong_aad() {
        let key = [0x42u8; 64];
        let nonce = [0x24u8; 32];
        let plaintext = b"Hello, Threefish-512!";
        
        let cipher = Threefish512Aead::new(&key).unwrap();
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, b"correct aad").unwrap();
        
        let result = cipher.decrypt(&nonce, &ciphertext, b"wrong aad");
        assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
    }
}
```

### 2.4 Maturin Build Config

**Datei:** `threefish_native/pyproject.toml`

```toml
[build-system]
requires = ["maturin>=1.4,<2.0"]
build-backend = "maturin"

[project]
name = "openssl-encrypt-threefish"
version = "1.0.0"
description = "Threefish-512 AEAD cipher for openssl-encrypt (256-bit PQ security)"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Rust",
    "Topic :: Security :: Cryptography",
]
keywords = ["cryptography", "threefish", "post-quantum", "encryption"]

[project.urls]
Homepage = "https://github.com/..."
Documentation = "https://..."
Repository = "https://github.com/..."

[tool.maturin]
features = ["pyo3/extension-module"]
python-source = "python"
module-name = "threefish_native"
strip = true
```

---

## Teil 3: Python Integration

### 3.1 Cipher Registry

**Datei:** `openssl_encrypt/modules/cipher_registry.py`

```python
"""
Cipher Registry - Abstraktionsschicht für verschiedene Cipher.

Ermöglicht einfaches Hinzufügen neuer Cipher ohne Core-Änderungen.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Dict, Type, Tuple
from enum import Enum


class CipherType(Enum):
    """Verfügbare Cipher-Typen."""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    THREEFISH_512 = "threefish-512"
    CASCADE = "cascade"  # AES → ChaCha → Threefish


@dataclass(frozen=True)
class CipherInfo:
    """Informationen über einen Cipher."""
    name: str
    key_size: int       # Bytes
    nonce_size: int     # Bytes
    tag_size: int       # Bytes
    pq_security_bits: int  # Post-Quantum Sicherheit
    description: str


class CipherBase(ABC):
    """Basis-Klasse für alle Cipher."""
    
    @classmethod
    @abstractmethod
    def info(cls) -> CipherInfo:
        """Gibt Cipher-Informationen zurück."""
        pass
    
    @abstractmethod
    def encrypt(
        self,
        key: bytes,
        nonce: bytes,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Verschlüsselt Daten.
        
        Returns:
            ciphertext + auth_tag
        """
        pass
    
    @abstractmethod
    def decrypt(
        self,
        key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Entschlüsselt Daten.
        
        Raises:
            AuthenticationError: Bei ungültigem Tag
        """
        pass
    
    @classmethod
    def generate_key(cls) -> bytes:
        """Generiert einen zufälligen Key."""
        import secrets
        return secrets.token_bytes(cls.info().key_size)
    
    @classmethod
    def generate_nonce(cls) -> bytes:
        """Generiert eine zufällige Nonce."""
        import secrets
        return secrets.token_bytes(cls.info().nonce_size)


class AuthenticationError(Exception):
    """Authentifizierung fehlgeschlagen."""
    pass


# ============================================================================
# Cipher Implementations
# ============================================================================

class AES256GCMCipher(CipherBase):
    """AES-256-GCM (Standard)."""
    
    @classmethod
    def info(cls) -> CipherInfo:
        return CipherInfo(
            name="AES-256-GCM",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            pq_security_bits=128,
            description="AES-256 in GCM mode (128-bit PQ security)"
        )
    
    def encrypt(self, key, nonce, plaintext, associated_data=None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        cipher = AESGCM(key)
        return cipher.encrypt(nonce, plaintext, associated_data)
    
    def decrypt(self, key, nonce, ciphertext, associated_data=None):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag
        cipher = AESGCM(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise AuthenticationError("AES-GCM authentication failed")


class ChaCha20Poly1305Cipher(CipherBase):
    """ChaCha20-Poly1305."""
    
    @classmethod
    def info(cls) -> CipherInfo:
        return CipherInfo(
            name="ChaCha20-Poly1305",
            key_size=32,
            nonce_size=12,
            tag_size=16,
            pq_security_bits=128,
            description="ChaCha20 with Poly1305 MAC (128-bit PQ security)"
        )
    
    def encrypt(self, key, nonce, plaintext, associated_data=None):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        cipher = ChaCha20Poly1305(key)
        return cipher.encrypt(nonce, plaintext, associated_data)
    
    def decrypt(self, key, nonce, ciphertext, associated_data=None):
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        from cryptography.exceptions import InvalidTag
        cipher = ChaCha20Poly1305(key)
        try:
            return cipher.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise AuthenticationError("ChaCha20-Poly1305 authentication failed")


class Threefish512Cipher(CipherBase):
    """Threefish-512 (Paranoia Mode - 256-bit PQ security)."""
    
    _available: Optional[bool] = None
    
    @classmethod
    def is_available(cls) -> bool:
        """Prüft ob Threefish verfügbar ist."""
        if cls._available is None:
            try:
                import threefish_native
                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available
    
    @classmethod
    def info(cls) -> CipherInfo:
        return CipherInfo(
            name="Threefish-512",
            key_size=64,
            nonce_size=32,
            tag_size=16,
            pq_security_bits=256,
            description="Threefish-512-CTR with Poly1305 (256-bit PQ security)"
        )
    
    def encrypt(self, key, nonce, plaintext, associated_data=None):
        if not self.is_available():
            raise RuntimeError(
                "Threefish not available. Install with: "
                "pip install openssl-encrypt[threefish]"
            )
        import threefish_native
        return threefish_native.encrypt(key, nonce, plaintext, associated_data)
    
    def decrypt(self, key, nonce, ciphertext, associated_data=None):
        if not self.is_available():
            raise RuntimeError(
                "Threefish not available. Install with: "
                "pip install openssl-encrypt[threefish]"
            )
        import threefish_native
        try:
            return threefish_native.decrypt(key, nonce, ciphertext, associated_data)
        except RuntimeError as e:
            if "Authentication failed" in str(e):
                raise AuthenticationError("Threefish-512 authentication failed")
            raise


class CascadeCipher(CipherBase):
    """
    Cipher Cascade: AES-256-GCM → ChaCha20-Poly1305 → Threefish-512
    
    Defense in Depth: Wenn einer gebrochen wird, schützen die anderen noch.
    """
    
    @classmethod
    def is_available(cls) -> bool:
        return Threefish512Cipher.is_available()
    
    @classmethod
    def info(cls) -> CipherInfo:
        return CipherInfo(
            name="Cascade",
            key_size=64,       # Für HKDF-Ableitung
            nonce_size=32,     # Größte Nonce (Threefish)
            tag_size=48,       # 3x 16-byte Tags
            pq_security_bits=256,
            description="AES-256 → ChaCha20 → Threefish-512 cascade (256-bit PQ, defense in depth)"
        )
    
    def _derive_keys(self, master_key: bytes, nonce: bytes) -> Tuple[bytes, bytes, bytes]:
        """Leitet 3 unabhängige Keys aus dem Master-Key ab."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        
        def derive(info: bytes, length: int) -> bytes:
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=length,
                salt=nonce[:16],  # Use part of nonce as salt
                info=info,
            )
            return hkdf.derive(master_key)
        
        aes_key = derive(b"cascade-aes-256-gcm", 32)
        chacha_key = derive(b"cascade-chacha20-poly1305", 32)
        threefish_key = derive(b"cascade-threefish-512", 64)
        
        return aes_key, chacha_key, threefish_key
    
    def _derive_nonces(self, base_nonce: bytes) -> Tuple[bytes, bytes, bytes]:
        """Leitet 3 unabhängige Nonces ab."""
        import hashlib
        
        aes_nonce = hashlib.sha256(b"nonce-aes" + base_nonce).digest()[:12]
        chacha_nonce = hashlib.sha256(b"nonce-chacha" + base_nonce).digest()[:12]
        threefish_nonce = hashlib.sha256(b"nonce-threefish" + base_nonce).digest()
        
        return aes_nonce, chacha_nonce, threefish_nonce
    
    def encrypt(self, key, nonce, plaintext, associated_data=None):
        if not self.is_available():
            raise RuntimeError(
                "Cascade requires Threefish. Install with: "
                "pip install openssl-encrypt[threefish]"
            )
        
        # Derive independent keys and nonces
        aes_key, chacha_key, threefish_key = self._derive_keys(key, nonce)
        aes_nonce, chacha_nonce, threefish_nonce = self._derive_nonces(nonce)
        
        # Layer 1: AES-256-GCM
        aes = AES256GCMCipher()
        ct1 = aes.encrypt(aes_key, aes_nonce, plaintext, associated_data)
        
        # Layer 2: ChaCha20-Poly1305
        chacha = ChaCha20Poly1305Cipher()
        ct2 = chacha.encrypt(chacha_key, chacha_nonce, ct1, associated_data)
        
        # Layer 3: Threefish-512
        threefish = Threefish512Cipher()
        ct3 = threefish.encrypt(threefish_key, threefish_nonce, ct2, associated_data)
        
        return ct3
    
    def decrypt(self, key, nonce, ciphertext, associated_data=None):
        if not self.is_available():
            raise RuntimeError(
                "Cascade requires Threefish. Install with: "
                "pip install openssl-encrypt[threefish]"
            )
        
        # Derive keys and nonces
        aes_key, chacha_key, threefish_key = self._derive_keys(key, nonce)
        aes_nonce, chacha_nonce, threefish_nonce = self._derive_nonces(nonce)
        
        # Layer 3: Threefish-512
        threefish = Threefish512Cipher()
        ct2 = threefish.decrypt(threefish_key, threefish_nonce, ciphertext, associated_data)
        
        # Layer 2: ChaCha20-Poly1305
        chacha = ChaCha20Poly1305Cipher()
        ct1 = chacha.decrypt(chacha_key, chacha_nonce, ct2, associated_data)
        
        # Layer 1: AES-256-GCM
        aes = AES256GCMCipher()
        plaintext = aes.decrypt(aes_key, aes_nonce, ct1, associated_data)
        
        return plaintext


# ============================================================================
# Registry
# ============================================================================

class CipherRegistry:
    """Registry für alle verfügbaren Cipher."""
    
    _ciphers: Dict[CipherType, Type[CipherBase]] = {
        CipherType.AES_256_GCM: AES256GCMCipher,
        CipherType.CHACHA20_POLY1305: ChaCha20Poly1305Cipher,
        CipherType.THREEFISH_512: Threefish512Cipher,
        CipherType.CASCADE: CascadeCipher,
    }
    
    @classmethod
    def get(cls, cipher_type: CipherType) -> CipherBase:
        """Gibt eine Cipher-Instanz zurück."""
        cipher_class = cls._ciphers.get(cipher_type)
        if cipher_class is None:
            raise ValueError(f"Unknown cipher: {cipher_type}")
        return cipher_class()
    
    @classmethod
    def get_by_name(cls, name: str) -> CipherBase:
        """Gibt Cipher nach String-Name zurück."""
        name_lower = name.lower()
        
        mapping = {
            "aes-256-gcm": CipherType.AES_256_GCM,
            "aes-gcm": CipherType.AES_256_GCM,
            "aes": CipherType.AES_256_GCM,
            "chacha20-poly1305": CipherType.CHACHA20_POLY1305,
            "chacha20": CipherType.CHACHA20_POLY1305,
            "chacha": CipherType.CHACHA20_POLY1305,
            "threefish-512": CipherType.THREEFISH_512,
            "threefish": CipherType.THREEFISH_512,
            "tf512": CipherType.THREEFISH_512,
            "cascade": CipherType.CASCADE,
            "paranoia": CipherType.CASCADE,
        }
        
        cipher_type = mapping.get(name_lower)
        if cipher_type is None:
            available = ", ".join(mapping.keys())
            raise ValueError(f"Unknown cipher '{name}'. Available: {available}")
        
        return cls.get(cipher_type)
    
    @classmethod
    def list_available(cls) -> Dict[str, CipherInfo]:
        """Listet alle verfügbaren Cipher."""
        result = {}
        for cipher_type, cipher_class in cls._ciphers.items():
            # Check availability
            if hasattr(cipher_class, 'is_available'):
                if not cipher_class.is_available():
                    continue
            result[cipher_type.value] = cipher_class.info()
        return result
    
    @classmethod
    def list_all(cls) -> Dict[str, Tuple[CipherInfo, bool]]:
        """Listet alle Cipher (auch nicht verfügbare)."""
        result = {}
        for cipher_type, cipher_class in cls._ciphers.items():
            available = True
            if hasattr(cipher_class, 'is_available'):
                available = cipher_class.is_available()
            result[cipher_type.value] = (cipher_class.info(), available)
        return result
```

### 3.2 CLI Integration

**Datei:** `openssl_encrypt/cli.py` (Erweiterung)

```python
@cli.command("ciphers")
@click.option("--all", "show_all", is_flag=True, help="Auch nicht installierte anzeigen")
def list_ciphers(show_all: bool):
    """Listet verfügbare Cipher auf."""
    from .modules.cipher_registry import CipherRegistry
    
    if show_all:
        ciphers = CipherRegistry.list_all()
        click.echo("Available ciphers:\n")
        for name, (info, available) in ciphers.items():
            status = "✓" if available else "✗ (not installed)"
            click.echo(f"  {name} {status}")
            click.echo(f"    Key: {info.key_size * 8}-bit, Nonce: {info.nonce_size * 8}-bit")
            click.echo(f"    PQ Security: {info.pq_security_bits}-bit")
            click.echo(f"    {info.description}")
            click.echo()
    else:
        ciphers = CipherRegistry.list_available()
        click.echo("Available ciphers:\n")
        for name, info in ciphers.items():
            click.echo(f"  {name}")
            click.echo(f"    {info.description}")
            click.echo(f"    PQ Security: {info.pq_security_bits}-bit")
            click.echo()


# Encrypt/Decrypt Commands erweitern
@cli.command("encrypt")
@click.option("--cipher", "-c", default="aes-256-gcm",
              help="Cipher: aes-256-gcm, chacha20, threefish-512, cascade")
@click.option("--for", "recipient", help="Recipient identity (asymmetric mode)")
# ... weitere Optionen
def encrypt_cmd(cipher: str, recipient: str, ...):
    """Verschlüsselt Dateien."""
    from .modules.cipher_registry import CipherRegistry
    
    cipher_impl = CipherRegistry.get_by_name(cipher)
    click.echo(f"Using cipher: {cipher_impl.info().name}")
    click.echo(f"PQ Security: {cipher_impl.info().pq_security_bits}-bit")
    
    # ...
```

---

## Teil 4: Metadaten-Format

### 4.1 Cipher-Info in Metadaten

```json
{
  "format_version": 7,
  "mode": "asymmetric",
  "encryption": {
    "algorithm": "threefish-512",
    "key_size": 512,
    "nonce": "<base64: 32 bytes>",
    "pq_security_bits": 256
  },
  "derivation_config": {
    "output_length": 64,
    "...": "..."
  }
}
```

Für Cascade:

```json
{
  "encryption": {
    "algorithm": "cascade",
    "layers": ["aes-256-gcm", "chacha20-poly1305", "threefish-512"],
    "key_size": 512,
    "nonce": "<base64: 32 bytes>",
    "pq_security_bits": 256
  }
}
```

---

## Teil 5: GitLab CI/CD Pipeline

### 5.1 Build Pipeline

**Datei:** `.gitlab-ci.yml`

```yaml
stages:
  - build
  - test
  - publish

variables:
  CARGO_HOME: ${CI_PROJECT_DIR}/.cargo

# Cache Rust dependencies
.rust-cache: &rust-cache
  cache:
    key: rust-${CI_COMMIT_REF_SLUG}
    paths:
      - .cargo/
      - threefish_native/target/

# ==============================================================================
# Build Wheels
# ==============================================================================

build:linux:
  stage: build
  <<: *rust-cache
  image: quay.io/pypa/manylinux2014_x86_64
  script:
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source $HOME/.cargo/env
    - pip install maturin
    - cd threefish_native
    - maturin build --release --strip -o dist
    # Build for multiple Python versions
    - for PYVER in cp310 cp311 cp312 cp313; do
        maturin build --release --strip -i /opt/python/${PYVER}-${PYVER}/bin/python -o dist;
      done
    - ls -la dist/
  artifacts:
    paths:
      - threefish_native/dist/*.whl
    expire_in: 1 week

build:macos-x86:
  stage: build
  <<: *rust-cache
  tags:
    - macos
    - x86_64
  script:
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source $HOME/.cargo/env
    - pip3 install maturin
    - cd threefish_native
    - maturin build --release --strip -o dist
  artifacts:
    paths:
      - threefish_native/dist/*.whl
    expire_in: 1 week

build:macos-arm:
  stage: build
  <<: *rust-cache
  tags:
    - macos
    - arm64
  script:
    - curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    - source $HOME/.cargo/env
    - pip3 install maturin
    - cd threefish_native
    - maturin build --release --strip -o dist
  artifacts:
    paths:
      - threefish_native/dist/*.whl
    expire_in: 1 week

build:windows:
  stage: build
  tags:
    - windows
  script:
    - choco install rustup.install -y
    - refreshenv
    - rustup default stable
    - pip install maturin
    - cd threefish_native
    - maturin build --release --strip -o dist
  artifacts:
    paths:
      - threefish_native/dist/*.whl
    expire_in: 1 week

# ==============================================================================
# Test
# ==============================================================================

test:rust:
  stage: test
  <<: *rust-cache
  image: rust:latest
  script:
    - cd threefish_native
    - cargo test --release
    - cargo bench --no-run  # Just compile benchmarks

test:python:
  stage: test
  image: python:3.11
  needs:
    - build:linux
  script:
    - pip install threefish_native/dist/*cp311*.whl
    - pip install pytest
    - python -c "import threefish_native; print(threefish_native.algorithm_info())"
    - pytest tests/test_threefish.py -v

# ==============================================================================
# Publish
# ==============================================================================

publish:pypi:
  stage: publish
  image: python:3.11
  needs:
    - build:linux
    - build:macos-x86
    - build:macos-arm
    - build:windows
    - test:rust
    - test:python
  rules:
    - if: $CI_COMMIT_TAG =~ /^v\d+\.\d+\.\d+/
  script:
    - pip install twine
    - twine upload threefish_native/dist/*.whl
  variables:
    TWINE_USERNAME: __token__
    TWINE_PASSWORD: ${PYPI_TOKEN}
```

---

## Teil 6: Tests

### 6.1 Python Tests

**Datei:** `tests/test_threefish.py`

```python
"""Tests für Threefish-512 Integration."""

import pytest
import secrets

# Skip if not installed
threefish_native = pytest.importorskip("threefish_native")


class TestThreefishNative:
    """Direkte Tests der Rust-Extension."""
    
    def test_constants(self):
        assert threefish_native.KEY_SIZE == 64
        assert threefish_native.NONCE_SIZE == 32
        assert threefish_native.TAG_SIZE == 16
    
    def test_roundtrip(self):
        key = threefish_native.generate_key()
        nonce = threefish_native.generate_nonce()
        plaintext = b"Hello, Threefish-512!"
        
        ciphertext = threefish_native.encrypt(key, nonce, plaintext, None)
        decrypted = threefish_native.decrypt(key, nonce, ciphertext, None)
        
        assert decrypted == plaintext
    
    def test_roundtrip_with_aad(self):
        key = threefish_native.generate_key()
        nonce = threefish_native.generate_nonce()
        plaintext = b"Secret data"
        aad = b"Additional authenticated data"
        
        ciphertext = threefish_native.encrypt(key, nonce, plaintext, aad)
        decrypted = threefish_native.decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_tampered_ciphertext_fails(self):
        key = threefish_native.generate_key()
        nonce = threefish_native.generate_nonce()
        plaintext = b"Secret"
        
        ciphertext = bytearray(threefish_native.encrypt(key, nonce, plaintext, None))
        ciphertext[0] ^= 0xFF  # Tamper
        
        with pytest.raises(RuntimeError, match="Authentication failed"):
            threefish_native.decrypt(key, nonce, bytes(ciphertext), None)
    
    def test_wrong_aad_fails(self):
        key = threefish_native.generate_key()
        nonce = threefish_native.generate_nonce()
        plaintext = b"Secret"
        
        ciphertext = threefish_native.encrypt(key, nonce, plaintext, b"correct")
        
        with pytest.raises(RuntimeError, match="Authentication failed"):
            threefish_native.decrypt(key, nonce, ciphertext, b"wrong")
    
    def test_invalid_key_size(self):
        with pytest.raises(ValueError, match="64 bytes"):
            threefish_native.encrypt(b"short", b"x" * 32, b"data", None)
    
    def test_invalid_nonce_size(self):
        with pytest.raises(ValueError, match="32 bytes"):
            threefish_native.encrypt(b"x" * 64, b"short", b"data", None)
    
    def test_large_data(self):
        """Test mit 10 MB Daten."""
        key = threefish_native.generate_key()
        nonce = threefish_native.generate_nonce()
        plaintext = secrets.token_bytes(10 * 1024 * 1024)
        
        ciphertext = threefish_native.encrypt(key, nonce, plaintext, None)
        decrypted = threefish_native.decrypt(key, nonce, ciphertext, None)
        
        assert decrypted == plaintext


class TestCipherRegistry:
    """Tests für Cipher Registry Integration."""
    
    def test_threefish_available(self):
        from openssl_encrypt.modules.cipher_registry import Threefish512Cipher
        assert Threefish512Cipher.is_available()
    
    def test_threefish_info(self):
        from openssl_encrypt.modules.cipher_registry import Threefish512Cipher
        info = Threefish512Cipher.info()
        
        assert info.key_size == 64
        assert info.nonce_size == 32
        assert info.pq_security_bits == 256
    
    def test_registry_get(self):
        from openssl_encrypt.modules.cipher_registry import (
            CipherRegistry, CipherType
        )
        
        cipher = CipherRegistry.get(CipherType.THREEFISH_512)
        assert cipher.info().name == "Threefish-512"
    
    def test_registry_get_by_name(self):
        from openssl_encrypt.modules.cipher_registry import CipherRegistry
        
        # Various aliases
        for name in ["threefish-512", "threefish", "tf512"]:
            cipher = CipherRegistry.get_by_name(name)
            assert cipher.info().name == "Threefish-512"


class TestCascadeCipher:
    """Tests für Cascade-Modus."""
    
    def test_cascade_available(self):
        from openssl_encrypt.modules.cipher_registry import CascadeCipher
        assert CascadeCipher.is_available()
    
    def test_cascade_roundtrip(self):
        from openssl_encrypt.modules.cipher_registry import CascadeCipher
        
        cipher = CascadeCipher()
        key = cipher.generate_key()
        nonce = cipher.generate_nonce()
        plaintext = b"Triple-encrypted secret!"
        aad = b"authenticated"
        
        ciphertext = cipher.encrypt(key, nonce, plaintext, aad)
        decrypted = cipher.decrypt(key, nonce, ciphertext, aad)
        
        assert decrypted == plaintext
    
    def test_cascade_size_overhead(self):
        """Cascade sollte 3x Tag-Size Overhead haben."""
        from openssl_encrypt.modules.cipher_registry import CascadeCipher
        
        cipher = CascadeCipher()
        key = cipher.generate_key()
        nonce = cipher.generate_nonce()
        plaintext = b"x" * 100
        
        ciphertext = cipher.encrypt(key, nonce, plaintext, None)
        
        # 3 layers × 16-byte tag = 48 bytes overhead
        expected_size = len(plaintext) + 48
        assert len(ciphertext) == expected_size
```

---

## Teil 7: Dokumentation

### 7.1 README für Threefish-Paket

**Datei:** `threefish_native/README.md`

```markdown
# openssl-encrypt-threefish

Threefish-512 AEAD cipher extension for [openssl-encrypt](https://github.com/...).

Provides **256-bit post-quantum security** (vs 128-bit for AES-256).

## Installation

```bash
pip install openssl-encrypt[threefish]
```

## Usage

### Command Line

```bash
# Single cipher
openssl_encrypt encrypt --cipher threefish-512 secret.txt

# Cascade mode (AES → ChaCha → Threefish)
openssl_encrypt encrypt --cipher cascade secret.txt
```

### Python API

```python
import threefish_native

# Generate key and nonce
key = threefish_native.generate_key()      # 64 bytes
nonce = threefish_native.generate_nonce()  # 32 bytes

# Encrypt
ciphertext = threefish_native.encrypt(key, nonce, plaintext, aad)

# Decrypt
plaintext = threefish_native.decrypt(key, nonce, ciphertext, aad)
```

## Security

| Cipher | Key Size | PQ Security |
|--------|----------|-------------|
| AES-256-GCM | 256-bit | 128-bit |
| ChaCha20-Poly1305 | 256-bit | 128-bit |
| **Threefish-512** | **512-bit** | **256-bit** |

Threefish-512 with CTR mode and Poly1305 authentication provides the highest
post-quantum security level available.

## Building from Source

Requires Rust toolchain:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
pip install maturin
cd threefish_native
maturin develop
```
```

---

## Teil 8: Implementierungsreihenfolge

### Phase 1: Rust Core (2-3 Tage)
1. Cargo-Projekt aufsetzen
2. `threefish_aead.rs` implementieren
3. Unit Tests in Rust
4. PyO3 Bindings

### Phase 2: Python Integration (1 Tag)
5. `cipher_registry.py` implementieren
6. Threefish-Cipher-Klasse
7. Cascade-Cipher-Klasse

### Phase 3: Build Pipeline (1 Tag)
8. Maturin-Konfiguration
9. GitLab CI für alle Plattformen
10. Test-Pipeline

### Phase 4: Integration (1 Tag)
11. CLI-Erweiterung (`--cipher`)
12. Metadaten-Format anpassen
13. Python-Tests
14. Dokumentation

### Phase 5: Release
15. Version bumpen
16. Wheels bauen
17. PyPI Upload
18. ROADMAP aktualisieren

---

## Offene Entscheidungen

1. **Threefish-1024?** 
   - Noch mehr Overkill, aber möglich
   - Empfehlung: Nur 512 (256-bit PQ reicht)

2. **Default Cipher ändern?**
   - Aktuell: AES-256-GCM
   - Option: Bei `[threefish]` Installation automatisch Cascade?
   - Empfehlung: Nein, explizit mit `--cipher`

3. **Performance-Warnung?**
   - Threefish ist ~2-3x langsamer als AES
   - Warnung bei großen Dateien anzeigen?

---

**Erstellt**: 27. Dezember 2025
**Für**: Claude Code Implementation
**Version**: 1.0
**Geschätzter Aufwand**: 5-7 Tage
