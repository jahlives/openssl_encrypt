//! Threefish AEAD: CTR Mode + Poly1305 Authentication
//!
//! Implements AEAD (Authenticated Encryption with Associated Data) for both
//! Threefish-512 and Threefish-1024 using CTR mode for encryption and Poly1305
//! for authentication (similar to ChaCha20-Poly1305 construction).
//!
//! Format: ciphertext || poly1305_tag (16 bytes)

use threefish::Threefish512;
use threefish::Threefish1024;
use poly1305::{Poly1305, universal_hash::UniversalHash};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Poly1305 tag size
const TAG_SIZE: usize = 16;

/// Error type for AEAD operations
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
            Self::InvalidKeyLength => write!(f, "Invalid key length"),
            Self::InvalidNonceLength => write!(f, "Invalid nonce length"),
            Self::AuthenticationFailed => write!(f, "Authentication failed"),
            Self::EncryptionFailed => write!(f, "Encryption failed"),
        }
    }
}

/// Threefish-512 AEAD Cipher (64-byte key, 32-byte nonce)
#[derive(ZeroizeOnDrop)]
pub struct Threefish512Aead {
    #[zeroize]
    key: [u8; 64],
}

impl Threefish512Aead {
    /// Block size for Threefish-512
    const BLOCK_SIZE: usize = 64;

    /// Create new AEAD instance
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 64 {
            return Err(AeadError::InvalidKeyLength);
        }

        let mut key_arr = [0u8; 64];
        key_arr.copy_from_slice(key);

        Ok(Self { key: key_arr })
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

    /// Convert nonce to Threefish tweak (first 16 bytes)
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
        let mut counter = [0u8; Self::BLOCK_SIZE];
        counter[..16].copy_from_slice(&nonce[16..32]);

        for (block_idx, chunk) in plaintext.chunks(Self::BLOCK_SIZE).enumerate() {
            // Set counter
            let block_num = (block_idx as u64).to_le_bytes();
            counter[16..24].copy_from_slice(&block_num);

            // Encrypt counter block to get keystream
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
        let mut block = [0u8; Self::BLOCK_SIZE];
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

/// Threefish-1024 AEAD Cipher (128-byte key, 64-byte nonce)
#[derive(ZeroizeOnDrop)]
pub struct Threefish1024Aead {
    #[zeroize]
    key: [u8; 128],
}

impl Threefish1024Aead {
    /// Block size for Threefish-1024
    const BLOCK_SIZE: usize = 128;

    /// Create new AEAD instance
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 128 {
            return Err(AeadError::InvalidKeyLength);
        }

        let mut key_arr = [0u8; 128];
        key_arr.copy_from_slice(key);

        Ok(Self { key: key_arr })
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
        if nonce.len() != 64 {
            return Err(AeadError::InvalidNonceLength);
        }

        // Derive tweak from first 16 bytes of nonce
        let tweak = self.nonce_to_tweak(nonce);

        // CTR encryption
        let ciphertext = self.ctr_encrypt(plaintext, nonce, &tweak)?;

        // Derive Poly1305 key from Threefish
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
        if nonce.len() != 64 {
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

    /// Convert nonce to Threefish tweak (first 16 bytes)
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
        let cipher = Threefish1024::new_with_tweak(&self.key, tweak);

        // Use bytes 16-32 of nonce as counter base
        let mut counter = [0u8; Self::BLOCK_SIZE];
        counter[..48].copy_from_slice(&nonce[16..64]);

        for (block_idx, chunk) in plaintext.chunks(Self::BLOCK_SIZE).enumerate() {
            // Set counter
            let block_num = (block_idx as u64).to_le_bytes();
            counter[48..56].copy_from_slice(&block_num);

            // Encrypt counter block to get keystream
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
        let cipher = Threefish1024::new_with_tweak(&self.key, tweak);

        // Use nonce as input, get first 32 bytes of output as Poly1305 key
        let mut block = [0u8; Self::BLOCK_SIZE];
        block[..64].copy_from_slice(nonce);
        block[64] = 0xFF;  // Domain separator

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
        mac.update_padded(aad);
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
    fn test_threefish512_roundtrip() {
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
    fn test_threefish512_tampered_ciphertext() {
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
    fn test_threefish1024_roundtrip() {
        let key = [0x42u8; 128];
        let nonce = [0x24u8; 64];
        let plaintext = b"Hello, Threefish-1024!";
        let aad = b"additional data";

        let cipher = Threefish1024Aead::new(&key).unwrap();

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_threefish1024_tampered_tag() {
        let key = [0x42u8; 128];
        let nonce = [0x24u8; 64];
        let plaintext = b"Hello, Threefish-1024!";

        let cipher = Threefish1024Aead::new(&key).unwrap();

        let mut ciphertext = cipher.encrypt(&nonce, plaintext, &[]).unwrap();

        // Tamper with tag (last 16 bytes)
        let len = ciphertext.len();
        ciphertext[len - 1] ^= 0xFF;

        let result = cipher.decrypt(&nonce, &ciphertext, &[]);
        assert!(matches!(result, Err(AeadError::AuthenticationFailed)));
    }
}
