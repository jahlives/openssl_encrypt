//! Threefish-512 and Threefish-1024 AEAD Python Bindings
//!
//! Provides Threefish-512 and Threefish-1024 in CTR mode with Poly1305 authentication.
//! Enables true 256-bit and 512-bit post-quantum security.

use pyo3::prelude::*;
use pyo3::exceptions::{PyValueError, PyRuntimeError};
use pyo3::types::PyBytes;
use zeroize::Zeroize;

mod threefish_aead;

use threefish_aead::{Threefish512Aead, Threefish1024Aead, AeadError};

/// Convert AEAD errors to Python exceptions
fn aead_error_to_py(err: AeadError) -> PyErr {
    match err {
        AeadError::InvalidKeyLength | AeadError::InvalidNonceLength => {
            PyValueError::new_err(err.to_string())
        },
        AeadError::AuthenticationFailed => {
            PyRuntimeError::new_err("Authentication failed: data may be corrupted or tampered")
        },
        AeadError::EncryptionFailed => {
            PyRuntimeError::new_err("Encryption failed")
        },
    }
}

// ============================================================================
// Threefish-512 Functions
// ============================================================================

/// Threefish-512 AEAD Encryption
///
/// Args:
///     key: 64 bytes (512 bits)
///     nonce: 32 bytes (256 bits)
///     plaintext: Data to encrypt
///     associated_data: Optional AAD for authentication
///
/// Returns:
///     ciphertext + 16-byte Poly1305 tag
#[pyfunction]
#[pyo3(signature = (key, nonce, plaintext, associated_data=None))]
fn encrypt_512<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate inputs
    if key.len() != 64 {
        return Err(PyValueError::new_err(
            format!("Threefish-512 key must be 64 bytes (512 bits), got {}", key.len())
        ));
    }
    if nonce.len() != 32 {
        return Err(PyValueError::new_err(
            format!("Threefish-512 nonce must be 32 bytes (256 bits), got {}", nonce.len())
        ));
    }

    let aad = associated_data.unwrap_or(&[]);

    let cipher = Threefish512Aead::new(key).map_err(aead_error_to_py)?;

    let ciphertext = cipher.encrypt(nonce, plaintext, aad)
        .map_err(aead_error_to_py)?;

    Ok(PyBytes::new(py, &ciphertext))
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
#[pyo3(signature = (key, nonce, ciphertext, associated_data=None))]
fn decrypt_512<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate inputs
    if key.len() != 64 {
        return Err(PyValueError::new_err(
            format!("Threefish-512 key must be 64 bytes (512 bits), got {}", key.len())
        ));
    }
    if nonce.len() != 32 {
        return Err(PyValueError::new_err(
            format!("Threefish-512 nonce must be 32 bytes (256 bits), got {}", nonce.len())
        ));
    }
    if ciphertext.len() < 16 {
        return Err(PyValueError::new_err(
            "Ciphertext too short (must include 16-byte tag)"
        ));
    }

    let aad = associated_data.unwrap_or(&[]);

    let cipher = Threefish512Aead::new(key).map_err(aead_error_to_py)?;

    let plaintext = cipher.decrypt(nonce, ciphertext, aad)
        .map_err(aead_error_to_py)?;

    Ok(PyBytes::new(py, &plaintext))
}

/// Generate a random 64-byte key for Threefish-512
#[pyfunction]
fn generate_key_512<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    use rand::RngCore;
    let mut key = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut key);
    let result = PyBytes::new(py, &key);
    key.zeroize();
    Ok(result)
}

/// Generate a random 32-byte nonce for Threefish-512
#[pyfunction]
fn generate_nonce_512<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    use rand::RngCore;
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    Ok(PyBytes::new(py, &nonce))
}

// ============================================================================
// Threefish-1024 Functions
// ============================================================================

/// Threefish-1024 AEAD Encryption
///
/// Args:
///     key: 128 bytes (1024 bits)
///     nonce: 64 bytes (512 bits)
///     plaintext: Data to encrypt
///     associated_data: Optional AAD for authentication
///
/// Returns:
///     ciphertext + 16-byte Poly1305 tag
#[pyfunction]
#[pyo3(signature = (key, nonce, plaintext, associated_data=None))]
fn encrypt_1024<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate inputs
    if key.len() != 128 {
        return Err(PyValueError::new_err(
            format!("Threefish-1024 key must be 128 bytes (1024 bits), got {}", key.len())
        ));
    }
    if nonce.len() != 64 {
        return Err(PyValueError::new_err(
            format!("Threefish-1024 nonce must be 64 bytes (512 bits), got {}", nonce.len())
        ));
    }

    let aad = associated_data.unwrap_or(&[]);

    let cipher = Threefish1024Aead::new(key).map_err(aead_error_to_py)?;

    let ciphertext = cipher.encrypt(nonce, plaintext, aad)
        .map_err(aead_error_to_py)?;

    Ok(PyBytes::new(py, &ciphertext))
}

/// Threefish-1024 AEAD Decryption
///
/// Args:
///     key: 128 bytes (1024 bits)
///     nonce: 64 bytes (512 bits)
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
#[pyo3(signature = (key, nonce, ciphertext, associated_data=None))]
fn decrypt_1024<'py>(
    py: Python<'py>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: Option<&[u8]>,
) -> PyResult<Bound<'py, PyBytes>> {
    // Validate inputs
    if key.len() != 128 {
        return Err(PyValueError::new_err(
            format!("Threefish-1024 key must be 128 bytes (1024 bits), got {}", key.len())
        ));
    }
    if nonce.len() != 64 {
        return Err(PyValueError::new_err(
            format!("Threefish-1024 nonce must be 64 bytes (512 bits), got {}", nonce.len())
        ));
    }
    if ciphertext.len() < 16 {
        return Err(PyValueError::new_err(
            "Ciphertext too short (must include 16-byte tag)"
        ));
    }

    let aad = associated_data.unwrap_or(&[]);

    let cipher = Threefish1024Aead::new(key).map_err(aead_error_to_py)?;

    let plaintext = cipher.decrypt(nonce, ciphertext, aad)
        .map_err(aead_error_to_py)?;

    Ok(PyBytes::new(py, &plaintext))
}

/// Generate a random 128-byte key for Threefish-1024
#[pyfunction]
fn generate_key_1024<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    use rand::RngCore;
    let mut key = [0u8; 128];
    rand::thread_rng().fill_bytes(&mut key);
    let result = PyBytes::new(py, &key);
    key.zeroize();
    Ok(result)
}

/// Generate a random 64-byte nonce for Threefish-1024
#[pyfunction]
fn generate_nonce_1024<'py>(py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
    use rand::RngCore;
    let mut nonce = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut nonce);
    Ok(PyBytes::new(py, &nonce))
}

// ============================================================================
// Python module definition
// ============================================================================

/// Python module definition
#[pymodule]
fn threefish_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Threefish-512 functions
    m.add_function(wrap_pyfunction!(encrypt_512, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_512, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_512, m)?)?;
    m.add_function(wrap_pyfunction!(generate_nonce_512, m)?)?;

    // Threefish-1024 functions
    m.add_function(wrap_pyfunction!(encrypt_1024, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt_1024, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key_1024, m)?)?;
    m.add_function(wrap_pyfunction!(generate_nonce_1024, m)?)?;

    // Constants for Threefish-512
    m.add("KEY_SIZE_512", 64)?;
    m.add("NONCE_SIZE_512", 32)?;

    // Constants for Threefish-1024
    m.add("KEY_SIZE_1024", 128)?;
    m.add("NONCE_SIZE_1024", 64)?;

    // Common constants
    m.add("TAG_SIZE", 16)?;
    m.add("VERSION", "1.0.0")?;

    Ok(())
}
